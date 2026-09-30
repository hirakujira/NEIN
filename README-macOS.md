# NEIN macOS 穩定權限版

[iOS 版本說明](README.md)

## NEIN macOS 26.4.2

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
