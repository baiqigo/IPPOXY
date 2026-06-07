# TURN Local Port Expansion 2026-06-08

- Worker host: `ip-proxy-turn-poc.khowk1isgv.workers.dev`
- UUID: `2523c510-9ff0-415b-9582-93949bfae7e3`
- Local TURN ports mapped: 25
- Source: 12 existing POC ports plus current clean TURN candidates not already local.
- Existing POC ports preserved: 12 (`19080-19091`)
- New ports to add: 13 (`19092-19104`)

## Port Map

| Port | Tag | TURN | Exit IP | Country | Type | RT ms |
|---:|---|---|---|---|---|---:|
| 19080 | `ippoxy-res-us-att-lubbock` | `turn://104.184.105.172:3478` | `104.184.105.172` | US | isp/isp | 272 |
| 19081 | `ippoxy-res-us-comcast-lafayette` | `turn://24.130.161.222:3478` | `24.130.161.222` | US | isp/isp | 613 |
| 19082 | `ippoxy-static-gb-bnw-london` | `turn://195.80.16.8:3478` | `195.80.16.8` | GB | business/isp | 1019 |
| 19083 | `ippoxy-res-fr-sfr-rhone` | `turn://77.200.201.104:3478` | `77.200.201.104` | FR | isp/isp | 1125 |
| 19084 | `ippoxy-res-es-vodafone-sabadell` | `turn://46.26.142.252:3478` | `46.26.142.252` | ES | isp/isp | 1170 |
| 19085 | `ippoxy-res-de-vodafone-heilbronn` | `turn://188.111.122.196:3478` | `188.111.122.196` | DE | isp/isp | 1240 |
| 19086 | `ippoxy-static-de-bielefeld-dfn` | `turn://212.201.138.103:3478` | `212.201.138.103` | DE | education/isp | 1284 |
| 19087 | `ippoxy-res-de-vodafone-hamburg` | `turn://77.20.212.9:3478` | `77.20.212.9` | DE | isp/isp | 1257 |
| 19088 | `ippoxy-static-nl-surf-amsterdam` | `turn://145.100.106.100:3478` | `145.100.106.100` | NL | education/isp | 1555 |
| 19089 | `ippoxy-res-it-panservice-rome` | `turn://212.66.105.99:3478` | `212.66.105.99` | IT | isp/isp | 1386 |
| 19090 | `ippoxy-static-jp-kanazawa` | `turn://133.28.25.48:3478` | `133.28.25.48` | JP | education/education | 1569 |
| 19091 | `ippoxy-static-de-prosieben` | `turn://test:test123@81.93.119.16:3478` | `81.93.119.1` | DE | business/business | 1161 |
| 19092 | `ippoxy-static-pt-instituto-superior-tecnico-areeiro-192-132-53-28` | `turn://test:test123@192.132.53.28:3478` | `192.132.53.28` | PT | business/government | 1329 |
| 19093 | `ippoxy-static-it-nbit-it-servizi-hosting-altamura-185-110-23-3` | `turn://185.110.23.3:3479` | `185.110.23.3` | IT | business/isp | 1372 |
| 19094 | `ippoxy-res-br-lv-consultoria-eireli-goi-nia-190-8-18-8` | `turn://190.8.18.8:3478` | `190.8.18.8` | BR | isp/isp | 1487 |
| 19095 | `ippoxy-static-jp-kanazawa-university-nonoichi-133-28-25-44` | `turn://133.28.25.44:3478` | `133.28.25.44` | JP | education/education | 1612 |
| 19096 | `ippoxy-res-ru-seaexpress-ltd-avtovo-83-68-35-165` | `turn://83.68.35.165:3478` | `83.68.35.165` | RU | isp/isp | 1614 |
| 19097 | `ippoxy-res-kr-korea-telecom-seongnam-si-61-74-68-17` | `turn://61.74.68.16:3479` | `61.74.68.17` | KR | isp/isp | 1737 |
| 19098 | `ippoxy-res-kr-korea-telecom-seongnam-si-61-74-68-4` | `turn://112.175.27.113:3479` | `61.74.68.4` | KR | isp/isp | 1744 |
| 19099 | `ippoxy-res-tw-chunghwa-telecom-co-ltd-taipei-211-20-1-40` | `turn://test:test123@211.20.1.40:3478` | `211.20.1.40` | TW | isp/isp | 1772 |
| 19100 | `ippoxy-res-id-pt-mora-telematika-indonesia-jakarta-103-154-112-220` | `turn://103.154.112.220:3478` | `103.154.112.220` | ID | isp/isp | 2186 |
| 19101 | `ippoxy-res-vn-fpt-telecom-company-ho-chi-minh-city-113-23-35-22` | `turn://113.23.35.22:3478` | `113.23.35.22` | VN | isp/isp | 2315 |
| 19102 | `ippoxy-res-my-tm-technology-services-sdn-b-george-town-218-208-86-13` | `turn://218.208.86.13:3478` | `218.208.86.13` | MY | isp/isp | 2360 |
| 19103 | `ippoxy-res-au-superloop-australia-pty-ltd-sydney-125-253-55-109` | `turn://125.253.55.109:3478` | `125.253.55.109` | AU | isp/isp | 2427 |
| 19104 | `ippoxy-res-br-nedel-telecom-ira-177-125-244-38` | `turn://177.125.244.38:3478` | `177.125.244.38` | BR | isp/isp | 4671 |

## Outputs

- `docs/ip-proxy/resin/turn_xray_pool_25.local.txt`: Resin local subscription for all mapped TURN ports.
- `docs/ip-proxy/resin/turn_xray_pool_delta_13.local.txt`: only the ports not yet present in the 12-port POC.
- `docs/ip-proxy/resin/turn_vless_pool_25.txt`: VLESS share links carrying TURN paths.
- `docs/ip-proxy/resin/xray_turn_pool_25.generated.json`: generated Xray client config draft.
- `docs/ip-proxy/research/runtime/turn_xray_pool_20260608.json`: structured mapping data.

## Next Runtime Step

Start or containerize the generated Xray client in the sandbox only after confirming the long-running process details. Verification target: each `127.0.0.1:<port>` returns the matching `Exit IP` through `curl -x socks5h://127.0.0.1:<port> https://api.ipify.org`.
