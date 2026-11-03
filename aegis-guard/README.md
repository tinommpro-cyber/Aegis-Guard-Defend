# Aegis Guard (Tauri 2)
Windows prerequisites: Rust (rustup, MSVC toolchain), Node 18+, WebView2, Visual Studio Build Tools.
```
npm install
npm run tauri icon path/to/1024x1024.png   # one-time, generates src-tauri/icons
npm run app:dev                            # run
npm run app:build                          # -> src-tauri/target/release/bundle/nsis/*.exe installer
```
Portable binary: src-tauri/target/release/aegis-guard.exe
