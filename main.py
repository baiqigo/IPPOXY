import os
import time
import json
from get_token import get_access_token
from mailhub_client import import_outlook_account
from outlook_flow_stats import append_event, attempt_id, build_attempt_event, compact_summary, probe_exit_ip, summarize_events
from concurrent.futures import ThreadPoolExecutor
from utils import random_email, generate_strong_password


RETRYABLE_REGISTER_FAILURES = {
    "entry_failed",
    "rate_or_abnormal_after_profile",
}


def retryable_register_failure(reason):
    return reason in RETRYABLE_REGISTER_FAILURES


def get_ip_failure_retries():
    raw = os.environ.get("OUTLOOK_IP_FAILURE_RETRIES", "1").strip()
    try:
        value = int(raw)
    except ValueError:
        print(f"[Warn: Config] - invalid OUTLOOK_IP_FAILURE_RETRIES={raw!r}; using 1", flush=True)
        return 1
    return max(0, value)


def run_registration_attempt(controller, attempt_index, total_attempts):
    if hasattr(controller, "begin_flow_proxy_identity"):
        controller.begin_flow_proxy_identity()
    if hasattr(controller, "reset_flow_failure"):
        controller.reset_flow_failure()

    page = None
    email = random_email()
    password = generate_strong_password()
    full_email = f"{email}{controller.email_suffix}"
    proxy_url = controller.thread_proxy_url() if hasattr(controller, "thread_proxy_url") else ""
    current_attempt_id = attempt_id(attempt_index)
    exit_probe = probe_exit_ip(proxy_url)

    try:
        page = controller.get_thread_page()
        print(
            f"[FlowAttempt] - attempt={attempt_index}/{total_attempts} email={full_email}",
            flush=True,
        )

        result = controller.outlook_register(page, email, password)
        failure = controller.get_flow_failure() if hasattr(controller, "get_flow_failure") else {"reason": ""}
        append_event(
            build_attempt_event(
                event="registration_attempt_result",
                attempt_id_value=current_attempt_id,
                attempt_index=attempt_index,
                total_attempts=total_attempts,
                full_email=full_email,
                proxy_url=proxy_url,
                exit_probe=exit_probe,
                success=result,
                failure=failure,
                result_stage="registration",
            )
        )
        return page, email, password, result, failure, current_attempt_id, proxy_url, exit_probe
    except Exception as e:
        if hasattr(controller, "set_flow_failure"):
            controller.set_flow_failure("flow_exception", {"stage": "registration_attempt", "error": repr(e)})
        print(e)
        failure = controller.get_flow_failure() if hasattr(controller, "get_flow_failure") else {"reason": "flow_exception"}
        append_event(
            build_attempt_event(
                event="registration_attempt_result",
                attempt_id_value=current_attempt_id,
                attempt_index=attempt_index,
                total_attempts=total_attempts,
                full_email=full_email,
                proxy_url=proxy_url,
                exit_probe=exit_probe,
                success=False,
                failure=failure,
                result_stage="registration_exception",
            )
        )
        return page, email, password, False, failure, current_attempt_id, proxy_url, exit_probe



# --- 不确定有无帮助 ---
# 0. 视窗大小
# 1. CDP 检测：wait_for_timeout --> time.sleep()
# 2. 使用 launch_persistent_context 
# 3. 避免短时间访问
# 4. 模拟真人轨迹

def process_single_flow(controller):
    page = None
    email = ""
    password = ""
    current_attempt_id = ""
    attempt_proxy_url = ""
    attempt_exit_probe = {"enabled": False, "ok": False}

    try:
        max_attempts = get_ip_failure_retries() + 1
        result = False
        failure = {"reason": ""}

        for attempt in range(1, max_attempts + 1):
            (
                page,
                email,
                password,
                result,
                failure,
                current_attempt_id,
                attempt_proxy_url,
                attempt_exit_probe,
            ) = run_registration_attempt(
                controller,
                attempt,
                max_attempts,
            )

            if result:
                break

            reason = failure.get("reason", "")
            print(
                f"[FlowAttempt] - failed attempt={attempt}/{max_attempts} reason={reason}",
                flush=True,
            )
            if attempt >= max_attempts or not retryable_register_failure(reason):
                break

            print(
                f"[FlowAttempt] - retrying after retryable IP/entry failure reason={reason}",
                flush=True,
            )
            controller.clean_up(page, "done_browser")
            page = None

        full_email = f"{email}{controller.email_suffix}" if email else ""
        if result and not controller.enable_oauth2:
            append_event(
                build_attempt_event(
                    event="flow_result",
                    attempt_id_value=current_attempt_id,
                    attempt_index=0,
                    total_attempts=max_attempts,
                    full_email=full_email,
                    proxy_url=attempt_proxy_url,
                    exit_probe=attempt_exit_probe,
                    success=True,
                    failure={"reason": ""},
                    result_stage="registration_success_no_oauth",
                )
            )
            return True
        elif not result:
            append_event(
                build_attempt_event(
                    event="flow_result",
                    attempt_id_value=current_attempt_id,
                    attempt_index=0,
                    total_attempts=max_attempts,
                    full_email=full_email,
                    proxy_url=attempt_proxy_url,
                    exit_probe=attempt_exit_probe,
                    success=False,
                    failure=failure,
                    result_stage="registration_failed",
                )
            )
            return False

        proxy_url = controller.thread_proxy_url() if hasattr(controller, "thread_proxy_url") else None
        token_result = get_access_token(page, email, password=password, proxy_url=proxy_url)
        if token_result[0]:
            refresh_token, access_token, expire_at =  token_result
            full_email = f"{email}{controller.email_suffix}"
            with open(os.path.join(os.path.dirname(__file__), 'Results', 'outlook_token.txt'), 'a', encoding='utf-8') as f2:
                f2.write(f"{full_email}---{password}---{refresh_token}---{access_token}---{expire_at}\n")

            mailhub_result = import_outlook_account(
                full_email,
                password,
                controller.oauth2_client_id,
                refresh_token,
            )
            if mailhub_result.get("enabled"):
                if mailhub_result.get("ok"):
                    data = mailhub_result.get("data", {})
                    print(
                        "[Success: MailHub Import] - "
                        f"{full_email} imported={data.get('imported')} "
                        f"duplicated={data.get('duplicated')} skipped={data.get('skipped')}"
                    )
                else:
                    print(f"[Error: MailHub Import] - {full_email} {mailhub_result}")
                    append_event(
                        build_attempt_event(
                            event="flow_result",
                            attempt_id_value=current_attempt_id,
                            attempt_index=0,
                            total_attempts=max_attempts,
                            full_email=full_email,
                            proxy_url=attempt_proxy_url,
                            exit_probe=attempt_exit_probe,
                            success=False,
                            failure={"reason": "mailhub_import_failed", "details": mailhub_result},
                            result_stage="mailhub_import",
                        )
                    )
                    return False

            print(f'[Success: TokenAuth] - {full_email}')
            append_event(
                build_attempt_event(
                    event="flow_result",
                    attempt_id_value=current_attempt_id,
                    attempt_index=0,
                    total_attempts=max_attempts,
                    full_email=full_email,
                    proxy_url=attempt_proxy_url,
                    exit_probe=attempt_exit_probe,
                    success=True,
                    failure={"reason": ""},
                    result_stage="token_mailhub_success",
                )
            )
            return True
        else:
            append_event(
                build_attempt_event(
                    event="flow_result",
                    attempt_id_value=current_attempt_id,
                    attempt_index=0,
                    total_attempts=max_attempts,
                    full_email=full_email,
                    proxy_url=attempt_proxy_url,
                    exit_probe=attempt_exit_probe,
                    success=False,
                    failure={"reason": "token_auth_failed", "details": {}},
                    result_stage="token_auth",
                )
            )
            return False

    except Exception as e:
        print(e)
        append_event(
            build_attempt_event(
                event="flow_result",
                attempt_id_value=current_attempt_id,
                attempt_index=0,
                total_attempts=0,
                full_email=f"{email}{controller.email_suffix}" if email else "",
                proxy_url=attempt_proxy_url,
                exit_probe=attempt_exit_probe,
                success=False,
                failure={"reason": "flow_exception", "details": {"error": repr(e)}},
                result_stage="flow_exception",
            )
        )
        return False
    
    finally:

        controller.clean_up(page, "done_browser")

def run_concurrent_flows(controller, concurrent_flows=10, max_tasks=100):
    task_counter = 0
    succeeded_tasks = 0
    failed_tasks = 0
    batch_started_at = int(time.time())

    with ThreadPoolExecutor(max_workers=concurrent_flows) as executor:
        running_futures = set()

        while task_counter < max_tasks or len(running_futures) > 0:
            done_futures = {f for f in running_futures if f.done()}
            for future in done_futures:
                try:
                    if future.result():
                        succeeded_tasks += 1
                    else:
                        failed_tasks += 1
                except Exception as e:
                    failed_tasks += 1
                    print(e)
                running_futures.remove(future)

            while len(running_futures) < concurrent_flows and task_counter < max_tasks:
                new_future = executor.submit(process_single_flow, controller)
                running_futures.add(new_future)
                task_counter += 1
                if max_tasks > 1 and task_counter % (max_tasks // 2) == 0:
                    print(f"已提交 {task_counter}/{max_tasks} 任务.")
                elif max_tasks == 1:
                    print(f"已提交 {task_counter}/{max_tasks} 任务.")

            time.sleep(0.5)

    print(f"\n[Result] - 共: {max_tasks}, 成功 {succeeded_tasks}, 失败 {failed_tasks}")
    batch_summary = compact_summary(summarize_events(since_ts=batch_started_at))
    print(f"[ResultDetail] - {json.dumps(batch_summary, ensure_ascii=False, sort_keys=True)}", flush=True)


if __name__ == "__main__":

    with open('config.json', 'r', encoding='utf-8') as f:
        data = json.load(f) 
    os.makedirs("Results", exist_ok=True)

    max_tasks = int(os.environ.get("OUTLOOK_MAX_TASKS", data["max_tasks"]))
    concurrent_flows = int(os.environ.get("OUTLOOK_CONCURRENT_FLOWS", data["concurrent_flows"]))

    if data["choose_browser"] =="patchright":
        from controllers.patchright_controller import PatchrightController
        selected_controller = PatchrightController()
    elif data["choose_browser"] =="playwright":
        from controllers.playwright_controller import PlaywrightController
        selected_controller = PlaywrightController()
    else:
        print("不支持的浏览器类型，填写patchright或者playwright")
  

    try:
        run_concurrent_flows(selected_controller, concurrent_flows, max_tasks)
    finally:
        selected_controller.clean_up(type="all_browser")
