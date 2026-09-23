# NEIN

NEIN 在德文中就是「不／不要（No）」的意思。

名字取自這個雙關：對 LINE 裡不想要的東西說「NEIN」。

除了副裝置登入相容性與介面調整之外，NEIN 也可以停用已分析的廣告 loader、隱藏廣告檢視，並封鎖已核對的廣告網域。

> NEIN to ads. NEIN to unnecessary clutter.<br>
> LINE, aber ohne Werbung. NEIN.


## 支援版本 📦

| LINE 版本 | 需要越獄 | 安裝方式 | 缺點 |
|---|---|---|---|
| 26.14.0 | 否 | 自己簽署 | 需要 iOS 18 以上，沒有推播通知（以下有解法） |

### LINE 26.14.0

* NEIN 需要解密過的 LINE IPA，如果沒有越獄裝置可以自己進行 IPA 解密，則請自行在網路上搜尋現成的 IPA。
* NEIN 會將主 App 名稱設為 `NEIN`、Bundle ID 設為 `kinta.ma.nein`，並預設使用香蕉圖示。
* 為避免誤觸原版連結，輸出版本不註冊 URL scheme。
* 完成後請使用自己的憑證和 provisioning profile 完整重簽名再安裝。修改版可正常收發訊息，但不支援推播通知。
* 重簽可以使用 [AltStore](https://altstore.io/) 或 [Sideloadly](https://sideloadly.io/)。

預設使用副裝置模式（偽裝成 iPad 登入），建議使用副裝置先嘗試，以免影響帳號與內容，若要在主帳號嘗試，請務必先備份所有資料。

```sh
python3 tools/main.py --keychain-compat --remove-ads --hide-promotional-tabs \
  jp.naver.line_26.14.0_und3fined.ipa \
  output/NEIN-26.14.0-secondary.ipa
```

`--remove-ads` 會停用已分析的廣告 loader、隱藏廣告檢視，並封鎖已核對的 LINE
廣告、Google Ads/IMA 與 Taboola 網域。封鎖清單保存在
[`ad_domains.txt`](ad_domains.txt)，可用以下指令從已核對的 IPA 重新產生：

```sh
python3 tools/scan_ad_domains.py jp.naver.line_26.14.0_und3fined.ipa ad_domains.txt
```

`--remove-ads` 刻意封鎖整個 Taboola 網域後綴，LINE News 與推薦內容可能無法載入。

若要改用 IPA 內其他替代圖示，可以用指定 `--icon` 指令指定圖示。

若要建立保留主手機登入流程的版本，加上 `--primary-login`：

```sh
python3 tools/main.py --keychain-compat --remove-ads --hide-promotional-tabs \
  --primary-login \
  jp.naver.line_26.14.0_und3fined.ipa \
  output/NEIN-26.14.0-primary.ipa
```

目前只支援 LINE 26.14.0。`--remove-ads` 會封鎖特定廣告網域，但不攔截聊天資料
或 LINE RPC。實際結果可能受伺服器設定或地區影響，安裝後請在真機逐項確認。

## 建議做法 📱

1. 依照上方步驟建立副裝置版本的 IPA。
2. 工具會預設使用 `kinta.ma.nein` 作為 Bundle ID；重簽時請保留此設定。
3. 將修改版安裝到裝置後，即可與原版 LINE 並存。
4. 保留原版 LINE 可用於接收通知，修改版則用於日常操作，享受順暢的 App 體驗。

## 原理 ⚙️

- LINE 會檢查裝置是否為 iPhone，本工具修改登入入口的條件跳轉為 iPad，不會全域偽裝裝置。
- 注入相容層，在 App Group 無法使用時改用 App 私有目錄，並處理部分 Keychain 不相容問題。
- 修改後需以自己的憑證和 provisioning profile 完整重簽。
- 工具會核對版本、build 和執行檔 SHA-256，只對已分析的版本套用修補。

## macOS 穩定權限版（LINE 26.4.2）

本 repo 也包含一個針對本機 macOS LINE 26.4.2（build 3955）的研究原型。
macOS 版 LINE 使用 Qt/QML，不能直接套用 iOS hook。穩定權限版採用兩層 App：
外層顯示為 `NEIN`，內層 LINE 保留原本的 `jp.naver.line.mac` Bundle ID，讓
LINE 的既有資料位置與登入流程維持相容；原始 `/Applications/LINE.app` 不會被修改。

建議使用 Developer ID 重新建置。以下指令會先建立內層 App，再建立可雙擊啟動的
外層 `NEIN.app`：

```sh
SIGNING_IDENTITY='Developer ID Application: JYITECH CO.,LTD (Q6F5UHP863)'

python3 tools/mac_main.py \
  /Applications/LINE.app \
  output/NEIN-26.4.2-same-id-stable.app \
  --bundle-identifier jp.naver.line.mac \
  --disable-qt-ad-hiding \
  --signing-identity "$SIGNING_IDENTITY"

python3 tools/build_same_id_launcher.py \
  output/NEIN-26.4.2-same-id-stable.app \
  output/NEIN.app \
  --signing-identity "$SIGNING_IDENTITY"
```

穩定版只攔截已核對的 `WKWebView` 廣告 URL，且不攔截 DNS、Qt/QML 或 Qt
Widgets 的可見性。先前的 Qt/QML 實驗 hook 可能造成登入視窗不出現、圖片卡住、
已讀狀態異常或 CPU 飆高，因此保留為明確選項但不納入穩定版。固定的每版本 runtime
路徑也避免啟動器每次建立隨機路徑，降低 macOS 重複詢問「存取其他 App 資料」的機率。
首次使用同一個 Bundle ID 仍可能需要在 macOS 權限提示中按下 Allow。

輸出 App 旁的 `.manifest.json` 會記錄版本、雜湊、Bundle ID、簽名與實際啟用的
功能。要建立安裝套件和拖放映像檔，可執行：

```sh
python3 tools/package_macos.py output/NEIN.app output \
  --base-name NEIN-26.4.2-stable-permissions --force
```

這會產生 `NEIN-26.4.2-stable-permissions.pkg` 和
`NEIN-26.4.2-stable-permissions.dmg`。`.pkg` 安裝到 `/Applications`，`.dmg`
則包含可拖放到 Applications 的 `NEIN.app`。套件是本機研究建置，未代表官方簽署或
公證；登入、訊息同步、已讀、頭像和圖片仍應在測試帳號逐項確認。

## 注意 ⚠️

- 不支援推播通知功能
- 不包含原版的分享、Widget、Siri 與 Apple Watch 擴充功能。
- `--remove-ads` 可能使 LINE News、推薦內容或嵌入式廣告影片無法載入。
- 只支援已核對的版本和 IPA，其他版本會拒絕處理。
- 請先備份 LINE 資料，再於測試裝置安裝。

## 免責聲明 📄

本專案僅供學術研究、相容性測試與教育用途，為非官方研究與修改工具，與 LINE、NAVER 或 Apple 無關。使用修改後的 IPA 可能造成帳號、聊天資料或通知功能異常，也可能違反相關服務條款。請先備份資料，並確認使用方式符合適用法令及相關服務條款；使用者須自行承擔所有風險與責任。
