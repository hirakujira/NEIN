# macOS 26.4.2 stable-permissions build

這份文件整理 `NEIN-26.4.2-stable-permissions.dmg` 對應的 source 變更與
驗證方式。它描述的是可重建的程式碼，不包含本機產生的 `.app`、`.pkg`、`.dmg`
或簽署憑證。

## 修改內容

- `tools/mac_main.py` 複製並驗證 LINE 26.4.2 / build 3955，將
  `NEINMacHooks.dylib` 注入主 Mach-O 的 arm64 與 x86_64 slice。
- `hooks/NEINMacHooks.mm` 只對已核對的廣告網域套用 `WKWebView` URL 替換；DNS
  interpose 與 Qt/QML、Qt Widgets 可見性 hook 都是 opt-in，穩定版明確關閉。
- `launcher/NEINLauncher.m` 啟動內層 LINE，並將每個 LINE 版本複製到固定的
  `~/Library/Application Support/NEIN/Runtime/LINE-<version>.app` 路徑，避免隨機
  runtime 路徑造成 macOS 每次重新詢問資料存取權限。
- `tools/build_same_id_launcher.py` 產生外層 `NEIN.app`，使用獨立的 launcher
  Bundle ID，但讓內層 LINE 保持 `jp.naver.line.mac`，並帶入原始 LINE 圖示。
- `tools/package_macos.py` 以 `pkgbuild` 產生 `/Applications` 安裝包，以 `hdiutil`
  產生拖放式 DMG。

## 穩定版邊界

穩定版沒有 DNS 攔截，也沒有 Qt/QML 元件隱藏。這是刻意的相容性取捨：Qt/QML
visibility hook 在早期測試曾造成登入視窗、圖片載入、已讀狀態和 CPU 使用率問題。
因此穩定版只保留較窄的 WebKit 廣告 URL 攔截，不處理聊天、登入或 LINE RPC 流量。

## 重建與打包

```sh
SIGNING_IDENTITY='Developer ID Application: JYITECH CO.,LTD (Q6F5UHP863)'

python3 tools/mac_main.py /Applications/LINE.app \
  output/NEIN-26.4.2-same-id-stable.app \
  --bundle-identifier jp.naver.line.mac \
  --disable-qt-ad-hiding \
  --signing-identity "$SIGNING_IDENTITY"

python3 tools/build_same_id_launcher.py \
  output/NEIN-26.4.2-same-id-stable.app output/NEIN.app \
  --signing-identity "$SIGNING_IDENTITY"

python3 tools/package_macos.py output/NEIN.app output \
  --base-name NEIN-26.4.2-stable-permissions --force
```

產物應為：

- `output/NEIN.app`
- `output/NEIN-26.4.2-stable-permissions.pkg`
- `output/NEIN-26.4.2-stable-permissions.dmg`

建置完成後應使用 `codesign --verify --deep --strict output/NEIN.app` 驗證 App，
並在測試帳號確認登入、訊息同步、已讀、頭像和圖片載入。
