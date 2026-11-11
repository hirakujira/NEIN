# NEIN

NEIN 在德文是「不」的意思：對 LINE 裡不想要的東西說「NEIN」。

NEIN 會修改 LINE 的 IPA，讓 iPhone 以副裝置身分登入，並可選擇移除廣告、隱藏推廣分頁等。

> NEIN to ads. NEIN to unnecessary clutter.<br>
> LINE, aber ohne Werbung. NEIN.


## 支援版本 📦

LINE 26.14.0、26.15.1、26.17.0，需要 iOS 18 以上。只接受已核對的 IPA，其他版本會拒絕處理。

macOS 版請看 [README-macOS.md](README-macOS.md)。

## 使用方式 📖

1. 準備解密過的 LINE IPA（沒有越獄裝置的話，請自行在網路上搜尋）。
2. 執行（推薦組合，開啟所有日常功能）：

   ```sh
   python3 tools/main.py --keychain-compat --remove-ads --hide-promotional-tabs \
     --collapse-friends-on-launch --enable-sticker-shop \
     jp.naver.line_26.17.0.ipa \
     output/NEIN-26.17.0.ipa
   ```

   使用 iPhone Duo 的話，再加上 `--iphone-duo`。

3. 用自己的憑證完整重簽後安裝，例如 [AltStore](https://altstore.io/) 或 [Sideloadly](https://sideloadly.io/)。重簽時請保留 Bundle ID `kinta.ma.nein`。

裝好的 App 叫 `NEIN`，可以和原版 LINE 並存。NEIN 收不到推播，建議保留原版 LINE 接收通知，平常用 NEIN。

預設以副裝置（偽裝成 iPad）登入。建議先用副裝置測試；若要用主帳號，請先備份所有資料。

## 選項 ⚙️

| 選項 | 說明 |
|---|---|
| `--keychain-compat` | 處理重簽後部分 Keychain 存取失敗的問題，建議開啟。 |
| `--remove-ads` | 停用廣告載入、隱藏廣告，並封鎖廣告網域（清單見 [`ad_domains.txt`](ad_domains.txt)）。 |
| `--hide-promotional-tabs` | 隱藏 VOOM、新聞、購物與「逛逛」分頁，並在分頁列加上「設定」。也可以在 5 秒內連點「主頁」10 次開啟設定。 |
| `--collapse-friends-on-launch` | 首頁的好友區塊預設收合，仍可手動展開。 |
| `--enable-sticker-shop` | 實驗性開啟貼圖商店。可以用在原版 LINE 儲值的代幣購買（26.17.0 已實測），NEIN 內無法儲值。 |
| `--iphone-duo` | 實驗性支援 iPhone Duo：填滿內外螢幕，展開時改用 iPad 版的左右雙欄版面（已實機測試）。 |
| `--primary-login` | 保留主手機的登入流程，不偽裝成 iPad。 |

廣告網域清單可以用 `python3 tools/scan_ad_domains.py <IPA> ad_domains.txt` 重新產生。

## 原理 🔧

- 只修改登入入口的裝置判斷，讓 LINE 以為是 iPad，不會全域偽裝裝置。
- 注入相容層，處理重簽後 App Group 與 Keychain 無法使用的問題。

## 注意 ⚠️

- 不支援推播通知。
- 不包含原版的分享、Widget、Siri 與 Apple Watch 擴充功能。
- NEIN 不接收 LINE 連結，連結會由原版 LINE 開啟。
- `--remove-ads` 可能讓 LINE News、推薦內容或廣告影片無法載入。
- `--iphone-duo` 的版本裝在其他 iOS 27 iPhone 上，也會有些微版面差異（例如預設邊距變為 0）。
- 請先備份 LINE 資料，再於測試裝置安裝。

## 免責聲明 📄

本專案僅供學術研究、相容性測試與教育用途，為非官方研究與修改工具，與 LINE、NAVER 或 Apple 無關。使用修改後的 IPA 可能造成帳號、聊天資料或通知功能異常，也可能違反相關服務條款。請先備份資料，並確認使用方式符合適用法令及相關服務條款；使用者須自行承擔所有風險與責任。
