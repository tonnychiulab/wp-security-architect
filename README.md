# WP Security Architect 🛡️

> **一個探索「非同步架構」的 WordPress 資安實驗專案。**
> 記錄我們如何學習打造一個穩定、不超時的增量掃描引擎。

![License](https://img.shields.io/badge/license-GPLv3-blue.svg) ![PHP](https://img.shields.io/badge/php-%3E%3D7.4-8892BF.svg) ![Status](https://img.shields.io/badge/status-active_development-green.svg)

## 📖 開發故事

為什麼要重新發明輪子？因為市面上大多數的掃描器都有一個致命缺陷：**它們試圖一次做太多事情。**

當你在一個擁有數萬個檔案或是數 GB 上傳資料的大型網站執行掃描時，傳統掃描器經常會撞到 **PHP 執行時間限制 (30秒)** 或 **記憶體限制**，導致「白畫面 (White Screen of Death)」或是掃描不完整。

**WP Security Architect** 不一樣。它像是一支螞蟻軍團：
*   **🐜 非同步增量掃描 (Async Incremental Scan)**：將「搬走一座山」的任務切分成數千個微型任務。
*   **⏱️ 3秒法則**：每次請求只執行 2-3 秒，然後暫停並儲存進度。
*   **♾️ 無限掃描**：無論網站有 100GB 還是更多資料，都能在不造成伺服器負擔的情況下完成掃描。

---

## 🤖 AI 特種部隊 (Powered by AI Agents)

本專案的獨特之處在於，它是由一支專業的 **AI 代理人團隊** 設計與建造的。每個 AI 都有獨特的「靈魂」與「技能」。

| 角色 | 代號 | 職責 |
| :--- | :--- | :--- |
| **架構師 (The Architect)** | `wp-security-architect` | **核心穩定性**。確保非同步引擎永遠不會讓網站掛掉。座右銘：*"慢就是順，順就是快。"* |
| **獵人 (The Hunter)** | `wp-malware-hunter` | **惡意軟體偵測**。使用反混淆 (Deobfuscation) 與熵值分析 (Entropy) 來找出隱藏的後門與 Webshell。 |
| **審計師 (The Auditor)** | `wp-code-auditor` | **漏洞掃描**。找出您自定義代碼中的 SQL Injection 與 XSS 漏洞。 |

> 🧠 **探索 AI 大腦**：查看 [.agent/](.agent/) 資料夾，了解這些角色的提示工程 (Prompt Engineering) 設計。

---

## 🛠️ 主要功能

### 1. 核心引擎 (The Architect)
*   **零影響掃描**：在背景執行，完全不影響前台訪客的瀏覽速度。
*   **故障安全模式 (Fail-Safe)**：遇到讀不到的檔案直接跳過並記錄，絕不讓程式崩潰。
*   **官方比對**：與 WordPress.org API 連線，瞬間驗證核心檔案是否被竄改。

### 2. 惡意獵捕 (The Hunter)
*   **反混淆技術**：能識破 `eval(base64_decode(...))` 等常見的偽裝手法。
*   **熵值分析**：標記亂度過高的可疑檔案（通常是被加密的惡意軟體）。
*   **YARA 規則模擬**：採用進階的特徵碼比對邏輯。

### 3. 代碼審計 (The Auditor)
*   **靜態分析 (SAST)**：掃描您的主題與外掛，找出不良的編碼習慣。
*   **SQLi 偵測**：抓出沒有使用 `prepare()` 的直接 SQL 查詢。
*   **XSS 偵測**：抓出沒有使用 `esc_html()` 的直接輸出。

---

## 🚀 快速開始

*(外掛目前正處於活躍開發階段)*

1.  將此儲存庫 Clone 到您的 `wp-content/plugins/` 資料夾：
    ```bash
    git clone https://github.com/yourusername/wp-security-architect.git
    ```
2.  在 WordPress 後台啟用外掛。
3.  前往 **Security Architect** -> **Dashboard**。
4.  點擊 **"Start Async Scan"** (開始非同步掃描)。

---

## 📚 跟著我們一起學

我們用 **平實的語言 (Plain Language)** 完整記錄了打造這個掃描器的過程。
請閱讀我們的 **[LEARN.MD](LEARN.MD)**，了解我們在開發過程中的技術決策、犯過的錯誤以及學到的教訓。

---

## 🤝 參與貢獻

我們遵循一份嚴格的「使用者優先」協作協定，位於 [.agent/rules/ssd.md](.agent/rules/ssd.md)。
如果您想參與貢獻，請確保您的代碼穩定、有詳細註解，並遵守「永不炸站」的開發哲學。

---

*Built with ❤️ and 🤖 Intelligence.*
