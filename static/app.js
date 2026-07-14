document.addEventListener('DOMContentLoaded', () => {
    // STATE MANAGERS
    let currentEventSource = null;
    let scanHistoryData = [];

    // CORE DOM NODES
    const navBtnScan = document.getElementById('nav-btn-scan');
    const navBtnHistory = document.getElementById('nav-btn-history');
    const navBtnAbout = document.getElementById('nav-btn-about');

    const viewScan = document.getElementById('view-scan');
    const viewHistory = document.getElementById('view-history');
    const viewAbout = document.getElementById('view-about');

    // SCAN PANEL DOM
    const scanForm = document.getElementById('scan-form');
    const targetUrlInput = document.getElementById('target-url');
    const sslInsecureCheck = document.getElementById('ssl-insecure');
    const startScanBtn = document.getElementById('start-scan-btn');
    const scanLauncherCard = document.getElementById('scan-launcher-card');
    const scanProgressCard = document.getElementById('scan-progress-card');
    const activeReportContainer = document.getElementById('active-report-container');

    const currentScanTarget = document.getElementById('current-scan-target');
    const liveStatusText = document.getElementById('live-status-text');
    const progressPercentage = document.getElementById('progress-percentage');
    const consoleOutput = document.getElementById('console-output');
    const clearConsoleBtn = document.getElementById('clear-console-btn');

    // REPORT VIEWER DOM
    const reportViewerContent = document.getElementById('report-viewer-content');
    const closeReportBtn = document.getElementById('close-report-btn');
    const downloadReportBtn = document.getElementById('download-report-btn');
    const deleteCurrentReportBtn = document.getElementById('delete-current-report-btn');

    // HISTORY DOM
    const historyListContainer = document.getElementById('history-list-container');
    const refreshHistoryBtn = document.getElementById('refresh-history-btn');
    const historySearch = document.getElementById('history-search');

    // TOAST DOM
    const toastNode = document.getElementById('toast');
    const toastTitle = document.getElementById('toast-title');
    const toastMessage = document.getElementById('toast-message');

    // ==========================================
    // NAVIGATION CONTROLLER
    // ==========================================
    const views = [
        { btn: navBtnScan, pane: viewScan },
        { btn: navBtnHistory, pane: viewHistory },
        { btn: navBtnAbout, pane: viewAbout }
    ];

    function switchView(targetId) {
        views.forEach(v => {
            if (v.btn.id === targetId) {
                v.btn.classList.add('active');
                v.pane.classList.add('active');
            } else {
                v.btn.classList.remove('active');
                v.pane.classList.remove('active');
            }
        });
        
        // If switching to history, trigger fresh load
        if (targetId === 'nav-btn-history') {
            loadScanHistory();
        }
    }

    views.forEach(v => {
        v.btn.addEventListener('click', () => switchView(v.btn.id));
    });

    // ==========================================
    // TOAST NOTIFICATIONS
    // ==========================================
    let toastTimeout = null;
    function showToast(title, message, type = 'info') {
        clearTimeout(toastTimeout);
        
        // Reset classes
        toastNode.className = 'notification-toast';
        toastNode.classList.add(type);
        
        // Set icon class
        const iconEl = toastNode.querySelector('i');
        iconEl.className = 'fa-solid toast-icon';
        if (type === 'success') iconEl.classList.add('fa-circle-check');
        else if (type === 'error') iconEl.classList.add('fa-circle-xmark');
        else if (type === 'warning') iconEl.classList.add('fa-triangle-exclamation');
        else iconEl.classList.add('fa-circle-info');

        toastTitle.innerText = title;
        toastMessage.innerText = message;
        
        toastNode.classList.remove('hidden');
        
        toastTimeout = setTimeout(() => {
            toastNode.classList.add('hidden');
        }, 5000);
    }

    // ==========================================
    // SCAN RUNNER & SSE MONITOR
    // ==========================================
    scanForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const url = targetUrlInput.value.trim();
        const insecure = sslInsecureCheck.checked;

        if (!url) return;

        // Reset UI status
        startScanBtn.disabled = true;
        scanLauncherCard.classList.add('hidden');
        activeReportContainer.classList.add('hidden');
        scanProgressCard.classList.remove('hidden');

        currentScanTarget.innerText = `Đang quét: ${url}`;
        liveStatusText.innerText = 'Đang gửi yêu cầu thực thi...';
        progressPercentage.innerText = 'KHỞI TẠO';
        consoleOutput.innerHTML = '';
        
        // Reset all stepper steps to pending
        document.querySelectorAll('.step').forEach(stepEl => {
            stepEl.className = 'step pending';
        });

        // Clear SSE connection if active
        if (currentEventSource) {
            currentEventSource.close();
        }

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url, insecure })
            });

            if (!response.ok) {
                const errData = await response.json();
                throw new Error(errData.detail || 'Khởi chạy quét thất bại');
            }

            const data = await response.json();
            const scanId = data.scan_id;
            
            // Connect SSE progress stream
            connectProgressStream(scanId);
            showToast('Quét Bắt Đầu', `Đã khởi chạy quy trình quét cho ${url}`, 'success');

        } catch (error) {
            showToast('Lỗi Khởi Chạy', error.message, 'error');
            resetScannerConsole();
        }
    });

    function connectProgressStream(scanId) {
        currentEventSource = new EventSource(`/api/scan/progress/${scanId}`);
        let currentStepId = null;

        currentEventSource.onmessage = (event) => {
            const data = JSON.parse(event.data);
            
            // 1. Process standard log lines
                if (data.type === 'log') {
                appendConsoleLine(data.message, data.status);
                
                // Update live status text
                    if (data.message.startsWith('[+]')) {
                    liveStatusText.innerText = `Giai đoạn hiện tại: ${data.message.substring(4)}`;
                }

                // 2. Stepper status state updates
                if (data.step) {
                    const stepNode = document.getElementById(`step-${data.step}`);
                    if (stepNode) {
                        // Clear active states of current steps
                        if (data.status === 'running') {
                            if (currentStepId && currentStepId !== data.step) {
                                const oldStep = document.getElementById(`step-${currentStepId}`);
                                // If running next step, make sure old one shows success if not already marked
                                if (oldStep && !oldStep.classList.contains('success') && !oldStep.classList.contains('failed')) {
                                    oldStep.className = 'step success';
                                }
                            }
                            currentStepId = data.step;
                            stepNode.className = 'step running';
                            progressPercentage.innerText = `ĐANG: ${data.step.toUpperCase()}`;
                        } else if (data.status === 'success') {
                            stepNode.className = 'step success';
                        } else if (data.status === 'failed') {
                            stepNode.className = 'step failed';
                        }
                    }
                }
            }

            // 3. Scan compilation completed
                if (data.type === 'done') {
                currentEventSource.close();
                currentEventSource = null;
                showToast('Quét Hoàn Thành', 'Báo cáo quét đã được tạo thành công.', 'success');
                
                // Mark all steps up to report as success
                document.querySelectorAll('.step').forEach(stepEl => {
                    if (!stepEl.classList.contains('failed')) {
                        stepEl.className = 'step success';
                    }
                });
                
                setTimeout(() => {
                    // Hide progress and load report details
                    scanProgressCard.classList.add('hidden');
                    loadReportDetails(data.report_id);
                }, 1000);
            }

            // 4. Critical scan failure
            if (data.type === 'error') {
                currentEventSource.close();
                currentEventSource = null;
                showToast('Quét Bị Hủy', `Lỗi động cơ quét: ${data.error}`, 'error');
                
                progressPercentage.innerText = 'TIẾN TRÌNH LỖI';
                progressPercentage.className = 'badge text-red';
                liveStatusText.innerText = 'Quá trình thực thi đã dừng.';
                
                if (currentStepId) {
                    const stepNode = document.getElementById(`step-${currentStepId}`);
                    if (stepNode) stepNode.className = 'step failed';
                }
                
                startScanBtn.disabled = false;
                // Add an explicit button to reset console
                appendConsoleLine(`[CRITICAL] Quá trình quét gặp lỗi: ${data.error}`, 'failed');
            }
        };

        currentEventSource.onerror = (err) => {
            console.error('SSE Error:', err);
            appendConsoleLine('[HỆ THỐNG] Kết nối nhật ký bị gián đoạn. Đang thử lại...', 'failed');
        };
    }

    function appendConsoleLine(text, status) {
        const line = document.createElement('div');
        line.className = 'console-line';
        
        // Match line styles based on text and status indicators
        if (status === 'failed' || text.includes('[CRITICAL]') || text.includes('failed:')) {
            line.classList.add('text-red');
        } else if (status === 'success' || text.startsWith('[+] Completed') || text.includes('saved:')) {
            line.classList.add('text-green');
        } else if (text.startsWith('[+]')) {
            line.classList.add('text-cyan');
            line.style.fontWeight = 'bold';
            line.style.marginTop = '8px';
        } else if (text.startsWith('    SQLi target:')) {
            line.classList.add('text-yellow');
        } else {
            line.classList.add('text-dim');
        }

        // Parse date timestamp
        const timeStr = new Date().toLocaleTimeString();
        line.innerText = `[${timeStr}] ${text}`;
        
        consoleOutput.appendChild(line);
        consoleOutput.scrollTop = consoleOutput.scrollHeight;
    }

        clearConsoleBtn.addEventListener('click', () => {
        consoleOutput.innerHTML = '<div class="console-line text-dim">Đã xóa nhật ký.</div>';
    });

    function resetScannerConsole() {
        startScanBtn.disabled = false;
        scanLauncherCard.classList.remove('hidden');
        scanProgressCard.classList.add('hidden');
        activeReportContainer.classList.add('hidden');
    }

    // Close Report Toolbar Button
    closeReportBtn.addEventListener('click', () => {
        activeReportContainer.classList.add('hidden');
        scanLauncherCard.classList.remove('hidden');
        startScanBtn.disabled = false;
    });

    // ==========================================
    // REPORT EXPLORER / VIEWER RENDERER
    // ==========================================
    async function loadReportDetails(reportId) {
        try {
            const res = await fetch(`/api/reports/${reportId}`);
            if (!res.ok) throw new Error('Không thể lấy dữ liệu báo cáo');
            const data = await res.json();

            renderReportHTML(reportId, data);
            
            // Show report pane
            scanLauncherCard.classList.add('hidden');
            scanProgressCard.classList.add('hidden');
            activeReportContainer.classList.remove('hidden');
            
            // Set toolbar action targets
            downloadReportBtn.href = `/api/reports/${reportId}/html`;
            deleteCurrentReportBtn.onclick = () => confirmDeleteReport(reportId, true);

            // Scroll viewer to top
            window.scrollTo({ top: 0, behavior: 'smooth' });

        } catch (error) {
            showToast('Lỗi Trình Xem', error.message, 'error');
            resetScannerConsole();
        }
    }

    function renderReportHTML(reportId, report) {
        const targetUrl = report.target_url || report.target || report.directory?.target_url || 'unknown';
        const dateStr = formatIsoDate(reportId);
        
        // Count metrics for overview metrics cards
        const missingHeaders = report.headers ? Object.values(report.headers).filter(present => !present).length : 0;
        const openPorts = report.nmap?.tcp ? report.nmap.tcp.length : 0;
        const directoryFindings = report.directory?.findings ? report.directory.findings.length : 0;
        
        const sqliFindings = report.sqli?.findings?.length || 0;
        const sqliConfirmed = report.sqli?.confirmed_findings?.length || 0;
        const totalSqli = sqliFindings + sqliConfirmed;
        
        const xssFindings = report.xss?.findings?.length || 0;
        
        // Dynamic Risk Rating Calculation
        let riskRating = "SAFE";
        let riskClass = "text-green";
        if (totalSqli > 0 || xssFindings > 0) {
            riskRating = "CRITICAL";
            riskClass = "text-red";
        } else if (openPorts > 3 || missingHeaders > 4 || directoryFindings > 5) {
            riskRating = "MEDIUM";
            riskClass = "text-yellow";
        } else if (missingHeaders > 2 || openPorts > 0) {
            riskRating = "LOW";
            riskClass = "text-cyan";
        }

        // Generate report templates
        let html = `
            <div class="report-grid">
                
                <!-- 1. METADATA BRIEF -->
                <div class="cyber-card glass-panel report-summary-card">
                    <div class="card-glow"></div>
                    <div class="report-summary-layout">
                        <div class="report-meta-info">
                                            <div class="meta-field">
                                                <span class="field-label">URL Mục Tiêu:</span>
                                                <span class="field-val text-cyan">${escapeHtml(targetUrl)}</span>
                                            </div>
                                            <div class="meta-field">
                                                <span class="field-label">Mã Quét:</span>
                                                <span class="field-val" style="font-family: var(--font-mono); font-size: 13px;">${reportId}</span>
                                            </div>
                                            <div class="meta-field">
                                                <span class="field-label">Hoàn Thành:</span>
                                                <span class="field-val">${dateStr}</span>
                                            </div>
                        </div>
                        <div class="report-score-panel">
                            <div class="score-badge">
                                <div class="score-num ${riskClass}">${riskRating}</div>
                                <div class="score-label">Assessment Severity</div>
                            </div>
                            <div class="score-badge">
                                <div class="score-num text-red">${totalSqli + xssFindings}</div>
                                <div class="score-label">Vulnerabilities</div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- 2. REPORT TABS LAYOUT -->
                <div class="report-tabs-layout">
                    <!-- Tab buttons -->
                    <div class="report-tab-buttons">
                        <button class="tab-btn active" data-pane="overview">
                            <span>Tổng Quan</span>
                            <span class="tab-badge"><i class="fa-solid fa-chart-simple"></i></span>
                        </button>
                        <button class="tab-btn" data-pane="headers">
                            <span>Headers</span>
                            <span class="tab-badge ${missingHeaders > 0 ? 'alert' : ''}">${missingHeaders} missing</span>
                        </button>
                        <button class="tab-btn" data-pane="ssl">
                            <span>SSL/TLS Certificate</span>
                            <span class="tab-badge">${report.ssl?.verification === 'enabled' ? 'Valid' : 'Bypassed'}</span>
                        </button>
                        <button class="tab-btn" data-pane="nmap">
                            <span>Port Mapping</span>
                            <span class="tab-badge">${openPorts} open</span>
                        </button>
                        <button class="tab-btn" data-pane="directory">
                            <span>Directory Enumeration</span>
                            <span class="tab-badge">${directoryFindings}</span>
                        </button>
                        <button class="tab-btn" data-pane="vulns">
                            <span>Vulnerabilities</span>
                            <span class="tab-badge ${totalSqli + xssFindings > 0 ? 'alert' : ''}">${totalSqli + xssFindings} detected</span>
                        </button>
                    </div>

                    <!-- Tab Content panes -->
                    <div class="report-tab-panes">
                        
                        <!-- TAB: OVERVIEW -->
                        <div class="tab-pane active" id="pane-overview">
                            <h3>Tổng Quan Đánh Giá</h3>
                            <p class="pane-desc">Tổng hợp tóm tắt và chỉ số sau khi quét.</p>
                            
                            <div class="tech-item-list">
                                <div class="tech-item">
                                    <div class="tech-icon"><i class="fa-solid fa-file-shield"></i></div>
                                    <div>
                                        <h5>Phân tích Header Bảo Mật</h5>
                                        <p>${missingHeaders === 0 ? 'Tất cả header bảo mật đã được thiết lập đúng.' : `Thiếu ${missingHeaders} header bảo mật chuẩn, làm tăng rủi ro MIME-sniffing hoặc framing.`}</p>
                                    </div>
                                </div>
                                <div class="tech-item">
                                    <div class="tech-icon"><i class="fa-solid fa-lock"></i></div>
                                    <div>
                                        <h5>SSL/TLS Cryptography Status</h5>
                                        <p>Certificate verification was ${report.ssl?.verification || 'unknown'}. Host expires: <span class="text-cyan">${escapeHtml(report.ssl?.expires || 'N/A')}</span></p>
                                    </div>
                                </div>
                                <div class="tech-item">
                                    <div class="tech-icon"><i class="fa-solid fa-network-wired"></i></div>
                                    <div>
                                        <h5>Nmap Port Findings</h5>
                                        <p>Found ${openPorts} active port services responding on standard scans. Port security audit should block unused connectors.</p>
                                    </div>
                                </div>
                                <div class="tech-item">
                                    <div class="tech-icon"><i class="fa-solid fa-folder-tree"></i></div>
                                    <div>
                                        <h5>Directory Enumeration Summary</h5>
                                        <p>Wordlist brute-forcing checked paths, returning ${directoryFindings} index listings with interesting status codes.</p>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- TAB: HEADERS -->
                        <div class="tab-pane" id="pane-headers">
                            <h3>Header HTTP Bảo Mật</h3>
                            <p class="pane-desc">Phân tích các header HTTP tiêu chuẩn bảo vệ phía client.</p>
                            ${renderHeadersTable(report.headers)}
                        </div>

                        <!-- TAB: SSL -->
                        <div class="tab-pane" id="pane-ssl">
                            <h3>Chi Tiết Chứng Chỉ SSL/TLS</h3>
                            <p class="pane-desc">Thông tin xác thực và tham số mã hoá.</p>
                            ${renderSslDetails(report.ssl)}
                        </div>

                        <!-- TAB: NMAP -->
                        <div class="tab-pane" id="pane-nmap">
                            <h3>Cổng Mạng Hoạt Động</h3>
                            <p class="pane-desc">Kết quả quét cổng (Nmap) hiển thị dịch vụ, giao thức và phiên bản.</p>
                            ${renderNmapTable(report.nmap)}
                        </div>

                        <!-- TAB: DIRECTORY -->
                        <div class="tab-pane" id="pane-directory">
                            <h3>Danh Mục Đã Thử</h3>
                            <p class="pane-desc">Các tệp và thư mục con được liệt kê từ danh sách từ khóa.</p>
                            ${renderDirectoryTable(report.directory)}
                        </div>

                        <!-- TAB: VULNERABILITIES -->
                        <div class="tab-pane" id="pane-vulns">
                            <h3>Nhật Ký Lỗ Hổng</h3>
                            <p class="pane-desc">Các vector SQLi và trường hợp phản chiếu XSS được phát hiện.</p>
                            ${renderVulnerabilitiesPane(report)}
                        </div>

                    </div>
                </div>

            </div>
        `;

        reportViewerContent.innerHTML = html;

        // Initialize Tab Event Listeners
        const tabBtns = reportViewerContent.querySelectorAll('.tab-btn');
        const tabPanes = reportViewerContent.querySelectorAll('.tab-pane');

        tabBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                const paneId = btn.getAttribute('data-pane');
                
                tabBtns.forEach(b => b.classList.remove('active'));
                tabPanes.forEach(p => p.classList.remove('active'));
                
                btn.classList.add('active');
                reportViewerContent.querySelector(`#pane-${paneId}`).classList.add('active');
            });
        });
    }

    // ==========================================
    // RENDER HELPERS (REPORT SECTIONS)
    // ==========================================
    
    function renderHeadersTable(headers) {
        if (!headers || headers.error) {
            return `<div class="no-findings-box text-red"><i class="fa-solid fa-circle-xmark"></i><p>Headers scan error: ${headers?.error || 'No data found'}</p></div>`;
        }
        
        let rows = '';
        for (const [header, present] of Object.entries(headers)) {
            const icon = present ? '<i class="fa-solid fa-circle-check text-green"></i>' : '<i class="fa-solid fa-circle-xmark text-red"></i>';
            const statusLabel = present ? '<span class="text-green" style="font-weight:600;">Present</span>' : '<span class="text-red" style="font-weight:600;">Missing</span>';
            let desc = '';
            
            if (header === 'Content-Security-Policy') desc = 'Controls resources the browser is allowed to load, preventing XSS and injection attacks.';
            else if (header === 'Strict-Transport-Security') desc = 'Enforces HTTPS connections, preventing man-in-the-middle attacks.';
            else if (header === 'X-Frame-Options') desc = 'Protects against clickjacking by preventing framing of this page.';
            else if (header === 'X-Content-Type-Options') desc = 'Prevents MIME-sniffing vulnerabilities, ensuring resources load with proper types.';
            else if (header === 'Referrer-Policy') desc = 'Governs what referrer details are sent when navigating away from this origin.';
            else if (header === 'Permissions-Policy') desc = 'Controls browser hardware features (e.g. camera, microphone, geolocation).';

            rows += `
                <tr>
                    <td style="font-weight: 700; width: 220px;">${header}</td>
                    <td style="width: 100px; text-align: center;">${icon}</td>
                    <td style="width: 100px;">${statusLabel}</td>
                    <td>${desc}</td>
                </tr>
            `;
        }

        return `
            <div class="report-table-wrapper">
                <table class="report-table">
                    <thead>
                        <tr>
                            <th>Security Header</th>
                            <th style="text-align: center;">Status</th>
                            <th>Assessment</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${rows}
                    </tbody>
                </table>
            </div>
        `;
    }

    function renderSslDetails(ssl) {
        if (!ssl || ssl.error) {
            return `<div class="no-findings-box text-red"><i class="fa-solid fa-circle-xmark"></i><p>SSL Scan error: ${ssl?.error || 'No SSL certificates found'}</p></div>`;
        }

        const verificationIcon = ssl.verification === 'enabled' 
            ? '<i class="fa-solid fa-shield-check text-green"></i> Validated' 
            : '<i class="fa-solid fa-shield-slash text-yellow"></i> Disabled (Insecure flag used)';

        let issuerRows = '';
        if (Array.isArray(ssl.issuer)) {
            ssl.issuer.forEach(part => {
                if (Array.isArray(part) && part[0]) {
                    issuerRows += `<div class="finding-detail-row"><span class="label">${part[0][0]}:</span> <code>${part[0][1]}</code></div>`;
                }
            });
        } else if (ssl.issuer) {
            issuerRows = `<pre>${escapeHtml(JSON.stringify(ssl.issuer, null, 2))}</pre>`;
        }

        let subjectRows = '';
        if (Array.isArray(ssl.subject)) {
            ssl.subject.forEach(part => {
                if (Array.isArray(part) && part[0]) {
                    subjectRows += `<div class="finding-detail-row"><span class="label">${part[0][0]}:</span> <code>${part[0][1]}</code></div>`;
                }
            });
        } else if (ssl.subject) {
            subjectRows = `<pre>${escapeHtml(JSON.stringify(ssl.subject, null, 2))}</pre>`;
        }

        return `
            <div class="findings-container">
                <div class="finding-card warning-card">
                    <div class="finding-card-header">
                        <div class="finding-title-group">
                            <h4>SSL Certificate Validation State</h4>
                            <div class="finding-target">${verificationIcon}</div>
                        </div>
                        <span class="finding-severity ${ssl.verification === 'enabled' ? 'medium' : 'high'}">${ssl.verification === 'enabled' ? 'Passed' : 'Bypassed'}</span>
                    </div>
                    
                    <div class="finding-detail-row"><span class="label">Not After:</span> <code class="text-cyan">${escapeHtml(ssl.expires || 'N/A')}</code></div>
                </div>

                <div class="finding-card warning-card" style="border-color: rgba(255,255,255,0.06); background: transparent;">
                    <h4>Subject Identity (Common Name)</h4>
                    <div style="margin-top: 14px;">
                        ${subjectRows || '<p class="text-dim">No subject metadata parsed.</p>'}
                    </div>
                </div>

                <div class="finding-card warning-card" style="border-color: rgba(255,255,255,0.06); background: transparent;">
                    <h4>Authority Issuer (CA Details)</h4>
                    <div style="margin-top: 14px;">
                        ${issuerRows || '<p class="text-dim">No issuer metadata parsed.</p>'}
                    </div>
                </div>
            </div>
        `;
    }

    function renderNmapTable(nmap) {
        if (!nmap || nmap.error || Object.keys(nmap).length === 0) {
            return `<div class="no-findings-box text-dim"><i class="fa-solid fa-circle-info"></i><p>Nmap Port Scan reports empty or host not reachable: ${nmap?.error || 'No ports found'}</p></div>`;
        }

        let rows = '';
        for (const [proto, list] of Object.entries(nmap)) {
            if (!Array.isArray(list)) continue;
            
            list.forEach(p => {
                rows += `
                    <tr>
                        <td style="font-weight: 700; width: 100px; text-transform: uppercase;">${proto}</td>
                        <td style="font-family: var(--font-mono); width: 120px; color: var(--accent-cyan);">${p.port}</td>
                        <td style="width: 140px;"><span class="badge text-green" style="border-color: rgba(0, 255, 102, 0.2);">${p.state}</span></td>
                        <td style="font-weight: 600;">${escapeHtml(p.service || 'unknown')}</td>
                    </tr>
                `;
            });
        }

        if (!rows) {
            return `<div class="no-findings-box text-dim"><i class="fa-solid fa-shield"></i><p>No open ports discovered in fast scan.</p></div>`;
        }

        return `
            <div class="report-table-wrapper">
                <table class="report-table">
                    <thead>
                        <tr>
                            <th>Protocol</th>
                            <th>Port Number</th>
                            <th>State</th>
                            <th>Service Signature</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${rows}
                    </tbody>
                </table>
            </div>
        `;
    }

    function renderDirectoryTable(directory) {
        if (!directory || directory.error || !directory.findings) {
            return `<div class="no-findings-box text-red"><i class="fa-solid fa-triangle-exclamation"></i><p>Directory brute-force failed: ${directory?.error || 'No directory data generated'}</p></div>`;
        }

        const findings = directory.findings;
        if (!findings || findings.length === 0) {
            return `<div class="no-findings-box text-dim"><i class="fa-solid fa-eye-slash"></i><p>No interesting directories discovered (Checked ${directory.tested_paths || 0} routes).</p></div>`;
        }

        let rows = '';
        findings.forEach(f => {
            rows += `
                <tr>
                    <td style="width: 140px; font-weight: 700;">
                        <span class="badge ${f.status_code === 200 ? 'text-green' : 'text-yellow'}" style="border-color: transparent; background: rgba(255, 255, 255, 0.05)">
                            HTTP ${f.status_code}
                        </span>
                    </td>
                    <td style="font-family: var(--font-mono); word-break: break-all;">
                        <a href="${escapeHtml(f.url)}" target="_blank" class="text-cyan" style="text-decoration:none;">
                            ${escapeHtml(f.url)}
                        </a>
                    </td>
                    <td style="font-family: var(--font-mono); text-align: right; color: var(--text-secondary); width: 140px;">
                        ${f.content_length} bytes
                    </td>
                </tr>
            `;
        });

        return `
            <div class="report-table-wrapper">
                <table class="report-table">
                    <thead>
                        <tr>
                            <th>Status Code</th>
                            <th>Access URL</th>
                            <th style="text-align: right;">Size</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${rows}
                    </tbody>
                </table>
            </div>
        `;
    }

    function renderVulnerabilitiesPane(report) {
        let cardsHtml = '';
        
        // 1. SQLi vulnerability extraction
        const sqli = report.sqli || {};
        const sqliConfirmed = sqli.confirmed_findings || [];
        const sqliFindings = sqli.findings || [];
        const sqliTested = sqli.tested_parameters || [];
        
        // Confirmed findings cards
        sqliConfirmed.forEach(f => {
            let techniques = '';
            if (Array.isArray(f.techniques)) {
                f.techniques.forEach(t => {
                    techniques += `
                        <div style="margin-top: 10px; padding-top: 10px; border-top: 1px dashed rgba(255,255,255,0.04);">
                            <div class="finding-detail-row"><span class="label">Type:</span> <code>${escapeHtml(t.type || 'N/A')}</code></div>
                            <div class="finding-detail-row"><span class="label">Technique:</span> <span>${escapeHtml(t.title || 'N/A')}</span></div>
                            <div class="finding-detail-row"><span class="label">Payload:</span> <code>${escapeHtml(t.payload || 'N/A')}</code></div>
                        </div>
                    `;
                });
            }
            
            cardsHtml += `
                <div class="finding-card">
                    <div class="finding-card-header">
                        <div class="finding-title-group">
                            <h4>SQL Injection Confirmed</h4>
                            <div class="finding-target">${escapeHtml(f.target_url || 'auto-discovered target')}</div>
                        </div>
                        <span class="finding-severity high">Critical Risk</span>
                    </div>
                    <div class="finding-detail-row"><span class="label">Parameter:</span> <code class="text-cyan">${escapeHtml(f.parameter || 'N/A')}</code></div>
                    <div class="finding-detail-row"><span class="label">Location:</span> <span>${escapeHtml(f.location || 'N/A')}</span></div>
                    ${techniques}
                </div>
            `;
        });

        // Dynamic findings cards
        sqliFindings.forEach(f => {
            cardsHtml += `
                <div class="finding-card">
                    <div class="finding-card-header">
                        <div class="finding-title-group">
                            <h4>SQL Injection Potential Findings</h4>
                            <div class="finding-target">${escapeHtml(f.target_url || 'auto-discovered target')}</div>
                        </div>
                        <span class="finding-severity high">High Risk</span>
                    </div>
                    <div class="finding-detail-row"><span class="label">Parameter:</span> <code>${escapeHtml(f.parameter || 'N/A')}</code></div>
                    <div class="finding-detail-row"><span class="label">Payload:</span> <code>${escapeHtml(f.payload || 'N/A')}</code></div>
                    ${f.notes ? `<div class="finding-detail-row"><span class="label">Notes:</span> <span>${escapeHtml(f.notes)}</span></div>` : ''}
                </div>
            `;
        });

        // 2. XSS vulnerability extraction
        const xss = report.xss || {};
        const xssFindings = xss.findings || [];
        
        xssFindings.forEach(f => {
            cardsHtml += `
                <div class="finding-card" style="border-color: rgba(255, 170, 0, 0.35); background: rgba(255, 170, 0, 0.02)">
                    <div class="finding-card-header">
                        <div class="finding-title-group">
                            <h4>Cross-Site Scripting (XSS) Reflection</h4>
                            <div class="finding-target">${escapeHtml(f.target_url || 'auto-discovered target')}</div>
                        </div>
                        <span class="finding-severity medium" style="background: rgba(255, 170, 0, 0.15); border-color: rgba(255, 170, 0, 0.3)">High Risk</span>
                    </div>
                    <div class="finding-detail-row"><span class="label">Parameter:</span> <code>${escapeHtml(f.parameter || 'N/A')}</code></div>
                    <div class="finding-detail-row"><span class="label">Payload:</span> <code>${escapeHtml(f.payload || 'N/A')}</code></div>
                    <div class="finding-detail-row"><span class="label">Evidence CN:</span> <span>${escapeHtml(f.notes || 'Reflection matched signature')}</span></div>
                </div>
            `;
        });

        // Render raw Sqlmap reports if exists
        let sqlmapRawHtml = '';
        if (sqli.raw_output) {
            sqlmapRawHtml = `
                <details class="raw-block">
                    <summary>View raw SQL Injection scan execution output</summary>
                    <pre>${escapeHtml(sqli.raw_output)}</pre>
                </details>
            `;
        }

        if (!cardsHtml) {
            return `
                <div class="no-findings-box">
                    <i class="fa-solid fa-circle-check text-green"></i>
                    <p>No confirmed SQL Injection or XSS vulnerabilities detected on targeted parameters.</p>
                    <p class="text-dim" style="font-size:12px; margin-top:8px;">Tested endpoints: ${sqliTested.length} parameters checked.</p>
                </div>
            `;
        }

        return `
            <div class="findings-container">
                ${cardsHtml}
                ${sqlmapRawHtml}
            </div>
        `;
    }

    // ==========================================
    // SCAN HISTORY LEDGER ACTIONS
    // ==========================================
    async function loadScanHistory() {
        try {
            const res = await fetch('/api/reports');
            if (!res.ok) throw new Error('Could not pull scan reports list');
            
            scanHistoryData = await res.json();
            renderHistoryCards(scanHistoryData);

        } catch (error) {
            showToast('Sync Error', error.message, 'error');
        }
    }

    function renderHistoryCards(reports) {
        if (!reports || reports.length === 0) {
            historyListContainer.innerHTML = `
                <div class="no-reports glass-panel">
                    <i class="fa-solid fa-folder-open"></i>
                    <p>No scan reports found on server storage ledger.</p>
                </div>
            `;
            return;
        }

        let html = '';
        reports.forEach(r => {
            const dateStr = formatIsoDate(r.id);
            
            // Stats configuration
            const hColor = r.stats.headers_missing > 0 ? 'alert' : 'success';
            const sColor = r.stats.ssl_verified ? 'success' : 'alert';
            const pColor = r.stats.open_ports > 0 ? 'alert' : 'success';
            const sqliColor = r.stats.sqli_count > 0 ? 'alert' : 'success';
            const xssColor = r.stats.xss_count > 0 ? 'alert' : 'success';

            html += `
                <div class="cyber-card glass-panel history-card" id="card-${r.id}">
                    <div class="card-glow"></div>
                    <div class="history-card-info">
                        <h4>${escapeHtml(r.target)}</h4>
                        <span class="date"><i class="fa-solid fa-calendar-days"></i> ${dateStr}</span>
                    </div>
                    <div class="history-card-stats">
                        <span class="stat-tag ${hColor}">Headers: -${r.stats.headers_missing}</span>
                        <span class="stat-tag ${sColor}">SSL: ${r.stats.ssl_verified ? 'Yes' : 'No'}</span>
                        <span class="stat-tag ${pColor}">Ports: ${r.stats.open_ports}</span>
                        <span class="stat-tag ${sqliColor}">SQLi: ${r.stats.sqli_count}</span>
                        <span class="stat-tag ${xssColor}">XSS: ${r.stats.xss_count}</span>
                    </div>
                    <div class="history-card-actions">
                        <button class="cyber-btn primary" onclick="viewReport('${r.id}')" style="padding: 8px 16px; font-size:12px;">
                            <span>Xem</span>
                        </button>
                        <button class="cyber-btn danger" onclick="deleteHistoryReport('${r.id}')" style="padding: 8px 12px; font-size:12px;">
                            <i class="fa-solid fa-trash-can"></i>
                        </button>
                    </div>
                </div>
            `;
        });

        historyListContainer.innerHTML = html;
    }

    // Refresh history ledger
    refreshHistoryBtn.addEventListener('click', loadScanHistory);

    // Search filter past reports
    historySearch.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase().trim();
        if (!query) {
            renderHistoryCards(scanHistoryData);
            return;
        }

        const filtered = scanHistoryData.filter(r => 
            r.target.toLowerCase().includes(query) || 
            r.id.toLowerCase().includes(query)
        );
        renderHistoryCards(filtered);
    });

    // History interaction actions exposed globally
    window.viewReport = (reportId) => {
        switchView('nav-btn-scan');
        loadReportDetails(reportId);
    };

    window.deleteHistoryReport = (reportId) => {
        confirmDeleteReport(reportId, false);
    };

    async function confirmDeleteReport(reportId, fromScannerView) {
        if (!confirm(`Bạn có chắc chắn muốn xóa báo cáo quét ${reportId}?`)) {
                return;
            }

        try {
            const res = await fetch(`/api/reports/${reportId}`, { method: 'DELETE' });
            if (!res.ok) throw new Error('Deletion failed');
            
            showToast('Report Deleted', 'Report removed from server storage.', 'success');
            
            if (fromScannerView) {
                // If on scan examine pane, return to input form
                resetScannerConsole();
            } else {
                // Remove card element
                const card = document.getElementById(`card-${reportId}`);
                if (card) card.remove();
                
                // Refresh data array
                scanHistoryData = scanHistoryData.filter(r => r.id !== reportId);
                if (scanHistoryData.length === 0) {
                    renderHistoryCards([]);
                }
            }

        } catch (error) {
            showToast('Delete Error', error.message, 'error');
        }
    }

    // ==========================================
    // UTILITY HELPER METHODS
    // ==========================================
    function formatIsoDate(filename) {
        // Matches report_YYYYMMDD_HHMMSS
        const match = filename.match(/report_(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})/);
        if (!match) return 'Unknown Date';
        
        const [_, y, m, d, hh, mm, ss] = match;
        return `${y}-${m}-${d} ${hh}:${mm}:${ss}`;
    }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }
});
