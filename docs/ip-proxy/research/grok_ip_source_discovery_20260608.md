# Grok IP Source Discovery 2026-06-08

- Model: `grok-4.20-multi-agent-high`
- Raw: `docs/ip-proxy/research/runtime/grok_ip_source_discovery_20260608_024414.raw.txt`
- Parsed JSON: `docs/ip-proxy/research/runtime/grok_ip_source_discovery_20260608_024414.json`
- Extracted URLs: 24

## Result

**IPPOXY 鍏紑鍙姄鍙栨潵婧愭绱㈡姤鍛婏紙2026骞?鏈堟洿鏂帮級**

鏈姤鍛婅仛鐒︿簬**鏄庣‘鍙懆鏈熸€ф媺鍙?*鐨勫叕寮€ URL銆丟itHub raw 鏂囦欢銆佸畼鏂?API銆佽闃呴〉闈㈠拰鑷姩缁存姢宸ュ叿浠撳簱銆傛墍鏈夋潵婧愬潎鏉ヨ嚜鍏紑鍒楄〃銆丟itHub 浠撳簱銆佸畼鏂?API 鎴栨暀绋嬩腑鏄庣‘鎻愬強鐨勫唴瀹癸紝涓ユ牸閬靛畧涓嶄娇鐢?FOFA/Shodan/Censys 绛夊叏缃戞帰娴嬬殑瑕佹眰銆傞噸鐐硅鐩?VPNGate/OpenGW/SSTP銆乧mliussss/edgetunnel/CF-Workers-TURN 鐢熸€併€佸厤璐?SOCKS5/HTTP 鍒楄〃銆侀摼寮?TURN锛坱urn:// 鏍煎紡锛夈€佽嚜鍔ㄩ噰闆?楠岃瘉/杈撳嚭宸ュ叿銆俒[1]](https://github.com/Delta-Kronecker/Vpn-Gate)[[2]](https://github.com/proxifly/free-proxy-list)[[3]](https://github.com/F0rc3Run)

**鐜版湁鏉ユ簮閲嶅鏍囨敞**锛?
- https://raw.githubusercontent.com/Delta-Kronecker/Vpn-Gate/refs/heads/main/sstp_hosts.txt锛?*閲嶅**锛屾爣璁颁负 duplicate锛屼笉璁″叆鏂版潵婧愶級銆?
- https://sub.cmliussss.net/vpngate 鍜?https://www.vpngate.net/api/iphone/锛?*閲嶅**锛孷PNGate 鐢熸€佹牳蹇冿紝涓嶅啀寤鸿閲嶅鎺ュ叆锛夈€?

### 鏂板彂鐜版潵婧愬垪琛?
浣跨敤琛ㄦ牸褰㈠紡鏍囨敞姣忔潯鐨勫叧閿睘鎬э紙source_type銆佸彲鐩存帴鎶撳彇銆侀璁″€欓€夐噺銆佹槸鍚﹀彲鑳戒綇瀹?ISP銆侀闄╋級銆傞璁￠噺鍩轰簬褰撳墠鍏紑浠撳簱鍏稿瀷瑙勬ā锛堜細闅忔椂闂存尝鍔級锛涢闄╀富瑕佽€冭檻鍏紑鍏嶈垂鍒楄〃鐨勪笉绋冲畾鎬с€佹綔鍦ㄥ皝绂佹垨閫熺巼闄愬埗锛涗綇瀹?ISP 鍒ゆ柇鍩轰簬蹇楁効鑰呰妭鐐规垨缁存姢鑰呮弿杩般€?

**SSTP / OpenGW / VPNGate 鐩稿叧锛堜紭鍏堟柊閲囬泦鍣級**
- **URL**: https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/refs/heads/main/sstp-configs/sstp_with_country.txt
  **source_type**: sstp_subscription / github_raw
  **鍙洿鎺ユ姄鍙?*: 鏄紙绾枃鏈紝鍙惈 sstp://vpn:vpn@host:443 鏍煎紡锛?
  **棰勮鍊欓€夐噺**: 50鈥?00锛堝甫鍥藉鏍囩锛屾瘡 ~6 灏忔椂鍒锋柊锛?
  **鏄惁鍙兘浣忓畢/ISP**: 鏄紙蹇楁効鑰?ISP 鑺傜偣涓轰富锛?
  **椋庨櫓**: 涓紙鍏嶈垂鍏叡 VPN锛岃妭鐐逛笉绋冲畾浣嗗鏈?鍙嶅鏌ョ敤閫斿父瑙侊級
  **澶囨敞**: 鍩轰簬 V2rayCollector 鑷姩缁存姢鐨勬柊 SSTP 鍒楄〃锛屽己鐑堜紭鍏堛€俒[3]](https://github.com/F0rc3Run)

**cmliussss / CF-Workers-TURN / Edgetunnel 鐢熸€?*
- **URL**: https://raw.githubusercontent.com/ToiCF/CF-Workers-TURN/main/turn_results.txt
  **source_type**: turn_list / github_raw
  **鍙洿鎺ユ姄鍙?*: 鏄?
  **棰勮鍊欓€夐噺**: 10鈥?00锛堥獙璇佸悗缁撴灉锛?
  **鏄惁鍙兘浣忓畢/ISP**: 娣峰悎锛堝叕寮€ TURN 鏈嶅姟鍣級
  **椋庨櫓**: 涓紙閫熺巼闄愬埗鍙兘锛岄€傚悎閾惧紡娴嬭瘯锛?
  **澶囨敞**: 鐩存帴鏉ヨ嚜 CF-Workers-TURN 浠撳簱锛屽畬缇庡尮閰嶇敓鎬佷笌閾惧紡 TURN 闇€姹傘€?
- **URL**: https://raw.githubusercontent.com/cmliu/Socks2Vlesssub/main/socks5api.txt
  **source_type**: socks_subscription / github_raw
  **鍙洿鎺ユ姄鍙?*: 鏄?
  **棰勮鍊欓€夐噺**: ~20鈥?0锛堝惈浣忓畢鏍囪锛?
  **鏄惁鍙兘浣忓畢/ISP**: 鏄紙澶氭爣璁癧浣忓畢IP]锛?
  **椋庨櫓**: 浣?
  **澶囨敞**: cmliussss 鐢熸€?SOCKS5 API/鍒楄〃鑱氬悎锛岄€傚悎瀵煎叆 Resin 鍓嶆娴嬨€?
- **URL**: https://raw.githubusercontent.com/cmliu/WorkerVless2sub/main/socks5Data
  **source_type**: socks_subscription / github_raw
  **鍙洿鎺ユ姄鍙?*: 鏄紙socks5://ip:port#CC 鏍煎紡锛?
  **棰勮鍊欓€夐噺**: 鏁板崄鑷崇櫨浣?
  **鏄惁鍙兘浣忓畢/ISP**: 鏄紙閮ㄥ垎浣忓畢锛?
  **椋庨櫓**: 涓?
  **澶囨敞**: 鐢ㄤ簬 CF Workers SOCKS5 姹狅紝涓?edgetunnel 鐢熸€侀珮搴﹀吋瀹广€俒[4]](https://github.com/cmliu/edgetunnel)
- **URL**: https://github.com/ToiCF/CF-Workers-TURN
  **source_type**: tool_only
  **鍙洿鎺ユ姄鍙?*: 閮ㄥ垎锛坮aw 鏂囦欢 + Turn.js 绀轰緥锛?
  **棰勮鍊欓€夐噺**: N/A锛堝伐鍏凤級
  **鏄惁鍙兘浣忓畢/ISP**: N/A
  **椋庨櫓**: 浣?
  **澶囨敞**: CF Workers + TURN 涓户瀹為獙浠撳簱锛屾敮鎸?VLESS over TURN 涓庢壂鎻忛獙璇侊紝鐢熸€佹牳蹇冨伐鍏枫€?
- **URL**: https://socks5.sub.cmliussss.net/
  **source_type**: tutorial_only / tool_only
  **鍙洿鎺ユ姄鍙?*: 閮ㄥ垎锛堢敓鎴愬櫒椤甸潰锛屽彲瀵煎叆澶栭儴鍒楄〃锛?
  **棰勮鍊欓€夐噺**: 渚濊禆杈撳叆鍒楄〃
  **鏄惁鍙兘浣忓畢/ISP**: N/A
  **椋庨櫓**: 浣?
  **澶囨敞**: Socks5 鈫?VLESS 璁㈤槄鐢熸垚鍣紝涓庣幇鏈?check.socks5.cmliussss.net 閰嶅浣跨敤銆俒[5]](https://sub.cmliussss.net/)

**鍏嶈垂 SOCKS5/HTTP 璁㈤槄涓?Raw 鍒楄〃锛堥€傚悎鎵归噺瀵煎叆鍚?Resin 鍒嗙被妫€娴嬶級**
- **URL**: https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt 锛堟垨瀵瑰簲 /data.json銆?proxies/all/data.txt锛?
  **source_type**: socks_subscription / github_raw
  **鍙洿鎺ユ姄鍙?*: 鏄?
  **棰勮鍊欓€夐噺**: 400鈥?00+ SOCKS5锛堝叏鍒楄〃鏇村锛?
  **鏄惁鍙兘浣忓畢/ISP**: 娣峰悎锛堜互 DC 涓轰富锛屽皯閲?ISP锛?
  **椋庨櫓**: 涓紙姣?5 鍒嗛挓楠岃瘉鏇存柊锛屼粛闇€鍋ュ悍妫€鏌ワ級
  **澶囨敞**: proxifly/free-proxy-list 鑷姩缁存姢浠撳簱浼樼鏉ユ簮锛屼篃鏈?HTTP 鐗堟湰銆俒[2]](https://github.com/proxifly/free-proxy-list)
- **URL**: https://api.proxyscrape.com/v4/free-proxy-list/get?protocol=socks5&format=txt&timeout=10000&country=all
  **source_type**: official_api / socks_subscription
  **鍙洿鎺ユ姄鍙?*: 鏄紙鏀寔鍙傛暟杩囨护锛?
  **棰勮鍊欓€夐噺**: 鏁扮櫨鑷虫暟鍗冿紙鍔ㄦ€侊級
  **鏄惁鍙兘浣忓畢/ISP**: 娣峰悎
  **椋庨櫓**: 涓€撻珮锛堥珮 churn锛?
  **澶囨敞**: ProxyScrape 瀹樻柟 API锛屽彲鍛ㄦ湡璋冪敤骞剁粨鍚?GitHub 闀滃儚銆俒[6]](https://proxyscrape.com/free-proxy-list)
- **URL**: https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt
  **source_type**: socks_subscription / github_raw
  **鍙洿鎺ユ姄鍙?*: 鏄?
  **棰勮鍊欓€夐噺**: 鏁扮櫨鑷冲崈浣?
  **鏄惁鍙兘浣忓畢/ISP**: 娣峰悎
  **椋庨櫓**: 楂橈紙缁忓吀鍒楄〃锛岄渶涓ユ牸杩囨护锛?
  **澶囨敞**: 闀挎湡缁存姢鐨勫厤璐逛唬鐞?raw 鍒楄〃銆?
- **URL**: https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5/proxies.json
  **source_type**: socks_subscription / github_raw
  **鍙洿鎺ユ姄鍙?*: 鏄?
  **棰勮鍊欓€夐噺**: 鏁扮櫨锛堝惈 geo/妫€鏌ヤ俊鎭級
  **鏄惁鍙兘浣忓畢/ISP**: 娣峰悎
  **椋庨櫓**: 涓?
  **澶囨敞**: 姣忓皬鏃舵鏌ユ洿鏂帮紝缁撴瀯鍖栬緭鍑鸿壇濂姐€?

**鑷姩缁存姢宸ュ叿/浠撳簱锛堝彲鍛ㄦ湡鎷夊彇杈撳嚭鍒楄〃鎴栧弬鑰冮€昏緫锛?*
- **URL**: https://github.com/proxifly/free-proxy-list
  **source_type**: tool_only
  **鍙洿鎺ユ姄鍙?*: 鏄紙鍏舵墍鏈?raw/JSON 鏂囦欢锛?
  **棰勮鍊欓€夐噺**: N/A锛堣仛鍚堝婧愬苟楠岃瘉锛?
  **鏄惁鍙兘浣忓畢/ISP**: N/A
  **椋庨櫓**: 浣?
  **澶囨敞**: 姣?5 鍒嗛挓鑷姩鎶撳彇銆侀獙璇併€佽緭鍑哄垎绫诲垪琛紙SOCKS5/HTTP 绛夛級锛屾槸浼樼 harvester 鍙傝€冧粨搴撱€?
- **URL**: https://github.com/F0rc3Run/F0rc3Run
  **source_type**: tool_only
  **鍙洿鎺ユ姄鍙?*: 鏄紙澶氫釜鍒嗙被 raw锛屽寘鎷?proxies.txt锛?
  **棰勮鍊欓€夐噺**: 澶氬崗璁暟鍗?
  **鏄惁鍙兘浣忓畢/ISP**: 娣峰悎
  **椋庨櫓**: 涓?
  **澶囨敞**: 鍩轰簬 V2rayCollector 鐨勮嚜鍔ㄩ噰闆?娴嬭瘯/杈撳嚭浠撳簱锛屾瘡 ~6 灏忔椂鍒锋柊锛屽寘鍚?SSTP 涓?SOCKS銆俒[3]](https://github.com/F0rc3Run)

**TURN/閾惧紡 TURN 浼樺厛鍒楄〃**
- **URL**: https://gist.githubusercontent.com/sagivo/3a4b2f2c7ac6e1b5267c2f1f59ac6c6b/raw
  **source_type**: turn_list
  **鍙洿鎺ユ姄鍙?*: 鏄紙瑙ｆ瀽 turn:host?transport=udp 涓?credential锛岃浆鎹负 turn://user:pass@host:port锛?
  **棰勮鍊欓€夐噺**: 5鈥?0+锛堝惈 numb.viagenie.ca銆乥istri銆乷penrelay 绛夌粡鍏稿叕鍏?TURN锛?
  **鏄惁鍙兘浣忓畢/ISP**: 閮ㄥ垎鍏叡鏈嶅姟鍣紙闈炰綇瀹呬负涓伙級
  **椋庨櫓**: 涓紙閮ㄥ垎鍙兘杩囨湡鎴栨湁浣跨敤闄愬埗锛屼絾閫傚悎閾惧紡娴嬭瘯锛?
  **澶囨敞**: 缁忓吀 WebRTC STUN/TURN 鍏紑鍒楄〃锛屼紭鍏堝尮閰嶁€滈摼寮?TURN 浠ｇ悊鈥濅笌 turn:// 闇€姹傘€俒[7]](https://gist.github.com/sagivo/3a4b2f2c7ac6e1b5267c2f1f59ac6c6b)

### 鍏朵粬璇存槑
- 澶у鏁?SOCKS5/HTTP 鍒楄〃涓烘暟鎹腑蹇冧负涓伙紝浣忓畢姣斾緥杈冧綆锛屼絾 cmliussss 鐩稿叧涓?VPNGate/SSTP 鏉ユ簮浣忓畢/ISP 灞炴€ф洿寮恒€?
- 鎵€鏈夋潵婧愬潎閫傚悎鈥滄媺鍙?鈫?Resin 鍋ュ悍妫€鏌ャ€佸潖鑺傜偣鍓旈櫎銆佺矘鎬х绾︺€佽疆鎹€佸垎绫伙紙SOCKS5/HTTP/VLESS/SSTP/TURN锛夆€濇祦绋嬨€?
- 宸ュ叿浠撳簱锛坱ool_only锛夊彲浣滀负 harvester 閫昏緫鍙傝€冩垨鐩存帴鐩戞帶鍏惰緭鍑虹殑 raw 鏂囦欢銆?
- 鏈彂鐜板ぇ閲忓叏鏂扳€淥penGW SSTP 闈欐€佽闃呪€濇垨鈥渟stp://vpn:vpn@鈥濈嫭绔嬪垪琛紝涓昏渚濊禆涓婅堪閲囬泦鍣ㄣ€?

### 寤鸿椹笂鎺ュ叆 harvester 鐨勫墠 10 涓叕寮€ URL
浠ヤ笅鎸変紭鍏堢骇锛圱URN/SSTP/cmliussss 鐢熸€?鈫?楂橀 SOCKS raw 鈫?宸ュ叿锛夋帓搴忥紝閫傚悎绔嬪嵆鍛ㄦ湡鎬ф媺鍙栨祴璇曪細

1. https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/refs/heads/main/sstp-configs/sstp_with_country.txt 锛堟柊 SSTP锛屽惈鍥藉锛屼紭鍏堬級
2. https://raw.githubusercontent.com/ToiCF/CF-Workers-TURN/main/turn_results.txt 锛堢敓鎬?TURN 缁撴灉锛?
3. https://gist.githubusercontent.com/sagivo/3a4b2f2c7ac6e1b5267c2f1f59ac6c6b/raw 锛堝叕鍏?TURN 鍑瘉鍒楄〃锛岄摼寮忎紭鍏堬級
4. https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt 锛堥珮棰戦獙璇?SOCKS5锛?
5. https://raw.githubusercontent.com/cmliu/Socks2Vlesssub/main/socks5api.txt 锛坈mliussss 浣忓畢 SOCKS 鍏ュ彛锛?
6. https://raw.githubusercontent.com/cmliu/WorkerVless2sub/main/socks5Data 锛堢敓鎬?SOCKS5 姹犳暟鎹級
7. https://api.proxyscrape.com/v4/free-proxy-list/get?protocol=socks5&format=txt 锛堝畼鏂瑰姩鎬?API锛屽彲鍔犲弬鏁帮級
8. https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt 锛堢粡鍏?SOCKS5 raw锛?
9. https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt 锛堝叏鍗忚琛ュ厖锛?
10. https://github.com/proxifly/free-proxy-list 锛坱ool_only 浠撳簱锛岀洃鎺у叾鏇存柊閫昏緫涓庢洿澶?raw锛?

**鎺ュ叆寤鸿**锛氬厛鎷夊彇 TURN/SSTP 鍒楄〃娴嬭瘯閾惧紡鍙敤鎬э紝鍐嶆壒閲忓鍏?SOCKS5/HTTP 鐢?Resin 杩涜鍋ュ悍妫€鏌ヤ笌鍒嗙被銆傚畾鏈熺洃鎺т粨搴撴洿鏂帮紙GitHub Actions 棰戠巼楂橈級銆傚闇€鏇村瑙ｆ瀽鑴氭湰鎴栫壒瀹氶〉闈㈡祻瑙堥獙璇侊紝鍙繘涓€姝ユ墿灞曘€?

鎶ュ憡鍩轰簬鍏紑鎼滅储涓庨〉闈㈠垎鏋愮紪鍒讹紝鎵€鏈?URL 鍧囧彲鐩存帴鐢ㄤ簬 setbox/Daytona 鐜涓嬬殑 harvester銆?

## Extracted URLs

- https://github.com/Delta-Kronecker/Vpn-Gate
- https://github.com/proxifly/free-proxy-list
- https://github.com/F0rc3Run
- https://raw.githubusercontent.com/Delta-Kronecker/Vpn-Gate/refs/heads/main/sstp_hosts.txt锛?*閲嶅**锛屾爣璁颁负
- https://sub.cmliussss.net/vpngate
- https://www.vpngate.net/api/iphone/锛?*閲嶅**锛孷PNGate
- https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/refs/heads/main/sstp-configs/sstp_with_country.txt
- https://raw.githubusercontent.com/ToiCF/CF-Workers-TURN/main/turn_results.txt
- https://raw.githubusercontent.com/cmliu/Socks2Vlesssub/main/socks5api.txt
- https://raw.githubusercontent.com/cmliu/WorkerVless2sub/main/socks5Data
- https://github.com/cmliu/edgetunnel
- https://github.com/ToiCF/CF-Workers-TURN
- https://socks5.sub.cmliussss.net/
- https://sub.cmliussss.net/
- https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt
- https://api.proxyscrape.com/v4/free-proxy-list/get?protocol=socks5&format=txt&timeout=10000&country=all
- https://proxyscrape.com/free-proxy-list
- https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt
- https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5/proxies.json
- https://github.com/F0rc3Run/F0rc3Run
- https://gist.githubusercontent.com/sagivo/3a4b2f2c7ac6e1b5267c2f1f59ac6c6b/raw
- https://gist.github.com/sagivo/3a4b2f2c7ac6e1b5267c2f1f59ac6c6b
- https://api.proxyscrape.com/v4/free-proxy-list/get?protocol=socks5&format=txt
- https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt
