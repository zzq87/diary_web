        // 全局状态
        let authToken = '';
        let currentUser = '';
        let currentUserRole = 'user';
        let sessionTimeout = 3600;
        let idleTimer = null;
        let autoSaveTimer = null;
        let searchDebounceTimer = null;
        let idleEventHandlers = [];
        let currentYear = new Date().getFullYear();
        let currentMonth = new Date().getMonth() + 1;
        let diaryDates = new Set();
        let _searchQuery = '';

        // 全局错误捕获，将 JS 错误显示为 Toast
        window.onerror = function (msg, url, line, col, err) {
            try {
                showToast('JS错误: ' + (err ? err.message : msg) + ' (行' + line + ')', 'error');
            } catch (e) { /* ignore */ }
        };

        // 优先从 cookie 获取 token（httpOnly，更安全）
        function getCookie(name) {
            const match = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
            return match ? match[2] : '';
        }

        // ─── 认证 ──────────────────────────────────────
        async function checkAuth() {
            // 优先使用 cookie（httpOnly），其次 localStorage 作为回退
            authToken = getCookie('diary_token') || localStorage.getItem('diary_token') || '';
            if (!authToken) {
                showLoginPage();
                return;
            }

            try {
                const res = await fetch('/api/auth/status', {
                    credentials: 'include'
                });
                const data = await res.json();

                if (data.authenticated) {
                    currentUser = data.username;
                    currentUserRole = data.role || 'user';
                    if (!data.password_changed) {
                        document.getElementById('passwordWarning').classList.add('show');
                    }
                    showApp();
                } else {
                    localStorage.removeItem('diary_token');
                    authToken = '';
                    showLoginPage();
                }
            } catch (err) {
                showLoginPage();
            }
        }

        function showLoginPage() {
            document.getElementById('loginPage').classList.add('show');
            document.getElementById('appContainer').style.display = 'none';
            document.getElementById('lockScreen').classList.remove('show');
        }

        function showApp() {
            document.getElementById('loginPage').classList.remove('show');
            document.getElementById('appContainer').style.display = 'block';
            document.getElementById('lockScreen').classList.remove('show');
            document.getElementById('currentUser').textContent = currentUser;
            var isAdmin = currentUserRole === 'admin';
            document.getElementById('usersNavLink').style.display = isAdmin ? 'inline-block' : 'none';
            document.getElementById('mobileUsersNav').style.display = isAdmin ? 'flex' : 'none';
            resetIdleTimer();
        }

        function dismissPasswordWarning() {
            document.getElementById('passwordWarning').classList.remove('show');
        }

        // ─── 事件绑定（替代 onclick 内联）──────────────
        function bindEvents() {
            // 登录表单
            document.getElementById('loginForm').addEventListener('submit', handleLogin);

            // 注册表单切换
            document.getElementById('showRegisterLink').addEventListener('click', (e) => {
                e.preventDefault();
                document.getElementById('loginFormContainer').style.display = 'none';
                document.getElementById('registerFormContainer').style.display = 'block';
            });
            document.getElementById('showLoginLink').addEventListener('click', (e) => {
                e.preventDefault();
                document.getElementById('registerFormContainer').style.display = 'none';
                document.getElementById('loginFormContainer').style.display = 'block';
            });
            document.getElementById('registerForm').addEventListener('submit', handleRegister);

            // 忘记密码
            document.getElementById('forgotPasswordLink').addEventListener('click', (e) => {
                e.preventDefault();
                new bootstrap.Modal(document.getElementById('forgotPasswordModal')).show();
            });

            // 密码警告提示
            document.getElementById('dismissPasswordWarningBtn').addEventListener('click', dismissPasswordWarning);
            document.getElementById('goToSettingsBtn').addEventListener('click', () => {
                showView('settings');
                document.getElementById('oldPassword').focus();
            });

            // 锁屏
            document.getElementById('lockBtn').addEventListener('click', lockScreen);
            document.getElementById('unlockBtn').addEventListener('click', handleUnlock);
            document.getElementById('lockPassword').addEventListener('keydown', (e) => {
                if (e.key === 'Enter') handleUnlock();
            });
            document.getElementById('logoutFromLock').addEventListener('click', (e) => {
                e.preventDefault();
                handleLogout();
            });

            // 登出
            document.getElementById('logoutBtn').addEventListener('click', handleLogout);

            // 搜索（带防抖）
            document.getElementById('searchInput').addEventListener('input', () => {
                clearTimeout(searchDebounceTimer);
                searchDebounceTimer = setTimeout(() => {
                    const query = document.getElementById('searchInput').value.trim();
                    if (query.length >= 2) searchDiaries();
                }, 500);
            });
            document.getElementById('searchInput').addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    clearTimeout(searchDebounceTimer);
                    searchDiaries();
                }
            });

            // 导航 — 直接绑定
            document.querySelectorAll('.app-nav-link, .mobile-nav-item').forEach(el => {
                el.addEventListener('click', (e) => { e.preventDefault(); showView(el.dataset.view); });
            });
            // 导航 — 事件委托（兜底）
            document.getElementById('appContainer').addEventListener('click', (e) => {
                const btn = e.target.closest('.app-nav-link, .mobile-nav-item');
                if (btn) {
                    e.preventDefault();
                    showView(btn.dataset.view);
                }
            });

            // 月份切换
            document.getElementById('prevMonth').addEventListener('click', () => changeMonth(-1));
            document.getElementById('nextMonth').addEventListener('click', () => changeMonth(1));

            // 编辑器操作
            document.getElementById('saveBtn').addEventListener('click', saveDiary);
            document.getElementById('deleteBtn').addEventListener('click', deleteDiary);
            document.getElementById('downloadBtn').addEventListener('click', downloadDiary);



            // 密码修改
            document.getElementById('changePasswordBtn').addEventListener('click', changePassword);

            // 备份
            document.getElementById('downloadBackupBtn').addEventListener('click', downloadBackup);
            document.getElementById('downloadDecryptedBackupBtn').addEventListener('click', downloadDecryptedBackup);
            document.getElementById('restoreBtn').addEventListener('click', () => {
                document.getElementById('restoreFileInput').click();
            });
            document.getElementById('restoreFileInput').addEventListener('change', (e) => restoreBackup(e.target));

            // 用户管理
            document.getElementById('addUserBtn').addEventListener('click', () => openUserModal());
            document.getElementById('cancelUserModal').addEventListener('click', closeUserModal);
            document.getElementById('saveUserBtn').addEventListener('click', saveUser);
            document.getElementById('cancelResetPassword').addEventListener('click', closeResetPasswordModal);
            document.getElementById('confirmResetPassword').addEventListener('click', confirmResetPassword);
            document.getElementById('clearSearchBtn').addEventListener('click', clearSearch);
        }

        async function handleLogin(e) {
            e.preventDefault();
            const btn = document.getElementById('loginBtn');
            const error = document.getElementById('loginError');
            btn.disabled = true;
            btn.textContent = '登录中...';
            error.style.display = 'none';

            const username = document.getElementById('loginUsername').value.trim();
            const password = document.getElementById('loginPassword').value;

            try {
                const res = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                const data = await res.json();

                if (res.ok) {
                    authToken = data.token;
                    currentUser = data.username;
                    currentUserRole = data.role || 'user';
                    sessionTimeout = data.session_timeout;
                    showApp();
                    loadDiaryList();
                    if (!data.password_changed) {
                        document.getElementById('passwordWarning').classList.add('show');
                    }
                } else {
                    error.textContent = data.detail || data.error || '用户名或密码错误';
                    error.style.display = 'block';
                }
            } catch (err) {
                error.textContent = '网络连接失败，请检查服务是否运行';
                error.style.display = 'block';
            }

            btn.disabled = false;
            btn.textContent = '登 录';
            return false;
        }

        async function handleRegister(e) {
            e.preventDefault();
            const btn = document.getElementById('registerBtn');
            const username = document.getElementById('registerUsername').value.trim();
            const password = document.getElementById('registerPassword').value;
            const confirmPassword = document.getElementById('registerConfirmPassword').value;

            if (!username || username.length < 2) {
                showToast('用户名至少 2 个字符', 'error');
                return;
            }
            if (username.length > 32) {
                showToast('用户名最多 32 个字符', 'error');
                return;
            }
            if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
                showToast('用户名只能包含字母、数字、下划线和连字符', 'error');
                return;
            }
            if (password.length < 6) {
                showToast('密码至少 6 个字符', 'error');
                return;
            }
            if (password !== confirmPassword) {
                showToast('两次输入的密码不一致', 'error');
                return;
            }

            btn.disabled = true;
            btn.textContent = '注册中...';

            try {
                const res = await fetch('/api/auth/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password, confirm_password: confirmPassword })
                });
                const data = await res.json();

                if (res.ok) {
                    showToast('✅ 注册成功，请登录');
                    document.getElementById('registerFormContainer').style.display = 'none';
                    document.getElementById('loginFormContainer').style.display = 'block';
                    document.getElementById('loginUsername').value = username;
                    document.getElementById('registerForm').reset();
                } else {
                    showToast(data.error, 'error');
                }
            } catch (err) {
                showToast('网络连接失败', 'error');
            }

            btn.disabled = false;
            btn.textContent = '注 册';
        }

        async function handleUnlock() {
            const password = document.getElementById('lockPassword').value;
            if (!password) return;

            try {
                const res = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: currentUser, password })
                });
                const data = await res.json();

                if (res.ok) {
                    authToken = data.token;
                    document.getElementById('lockScreen').classList.remove('show');
                    resetIdleTimer();
                    showToast('已解锁');
                } else {
                    showToast(data.detail || data.error || '密码错误', 'error');
                }
            } catch (err) {
                showToast('网络错误', 'error');
            }
        }

        async function handleLogout() {
            try {
                await fetch('/api/logout', {
                    method: 'POST',
                    credentials: 'include'
                });
            } catch (e) {}
            
            localStorage.removeItem('diary_token');
            authToken = '';
            currentUser = '';
            clearIdleEventHandlers();
            clearTimeout(idleTimer);
            showLoginPage();
            showToast('已退出登录');
        }

        function lockScreen() {
            document.getElementById('lockScreen').classList.add('show');
            document.getElementById('lockPassword').value = '';
            document.getElementById('lockPassword').focus();
            clearIdleEventHandlers();
            clearTimeout(idleTimer);
        }

        // ─── 空闲检测（带事件监听器清理）──
        function clearIdleEventHandlers() {
            idleEventHandlers.forEach(({ event, handler, opts }) => {
                document.removeEventListener(event, handler, opts);
            });
            idleEventHandlers = [];
        }

        function resetIdleTimer() {
            clearTimeout(idleTimer);
            clearIdleEventHandlers();

            idleTimer = setTimeout(() => {
                lockScreen();
            }, sessionTimeout * 1000);

            const handler = () => {
                clearTimeout(idleTimer);
                idleTimer = setTimeout(() => {
                    lockScreen();
                }, sessionTimeout * 1000);
            };

            const events = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart'];
            events.forEach(evt => {
                const opts = (evt === 'scroll' || evt === 'touchstart') ? { once: true, passive: true } : { once: true };
                document.addEventListener(evt, handler, opts);
                idleEventHandlers.push({ event: evt, handler, opts });
            });
        }

        // ─── 请求拦截器 ────────────────────────────────
        async function apiFetch(url, options = {}) {
            const headers = {
                ...options.headers
            };
            if (authToken) {
                headers['X-Auth-Token'] = authToken;
            }

            if (options.body && typeof options.body === 'object') {
                headers['Content-Type'] = 'application/json';
                options.body = JSON.stringify(options.body);
            }

            try {
                const res = await fetch(url, {
                    ...options,
                    headers,
                    credentials: 'include'
                });

                if (res.headers.get('X-Session-Expired') === 'true' || res.status === 401) {
                    localStorage.removeItem('diary_token');
                    authToken = '';
                    lockScreen();
                    showToast('会话已过期，请重新登录', 'warning');
                    return null;
                }

                return res;
            } catch (err) {
                showToast('网络错误', 'error');
                return null;
            }
        }

        // ─── Toast ─────────────────────────────────────
        function showToast(message, type = 'success') {
            const toast = document.getElementById('toast');
            toast.textContent = message;
            toast.className = 'toast ' + type;
            toast.classList.add('show');
            setTimeout(() => toast.classList.remove('show'), 3000);
        }

        // ─── 视图切换 ──────────────────────────────────
        function showView(viewName) {
            try {
                document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
                document.querySelectorAll('.app-nav-link').forEach(l => l.classList.remove('active'));
                document.querySelectorAll('.mobile-nav-item').forEach(l => l.classList.remove('active'));

                const target = document.getElementById(viewName + 'View');
                if (!target) { showToast('视图 ' + viewName + ' 不存在', 'error'); return; }
                target.classList.add('active');

                // 高亮桌面导航
                document.querySelectorAll('.app-nav-link').forEach(l => {
                    if (l.dataset.view === viewName) l.classList.add('active');
                });

                // 高亮移动导航
                document.querySelectorAll('.mobile-nav-item').forEach(l => {
                    if (l.dataset.view === viewName) l.classList.add('active');
                });

                if (viewName === 'list') {
                    if (!_searchQuery) {
                        document.getElementById('searchStatus').style.display = 'none';
                    }
                    loadDiaryList();
                }
                if (viewName === 'calendar') loadCalendar();
                if (viewName === 'stats') loadStats();
                if (viewName === 'audit') loadAudit();
                if (viewName === 'users') loadUsers();
                if (viewName === 'settings') loadSettings();
                if (viewName === 'editor') {
                    document.getElementById('editorDate').value = new Date().toISOString().split('T')[0];
                }
            } catch (err) {
                showToast('视图切换错误: ' + err.message, 'error');
            }
        }

        // ─── 日记列表 ──────────────────────────────────
        async function loadDiaryList() {
            const list = document.getElementById('diaryList');
            list.innerHTML = Array.from({length: 4}, () => `
                <div class="skeleton-item">
                    <div class="skeleton-line"></div>
                    <div class="skeleton-line"></div>
                    <div class="skeleton-line"></div>
                </div>
            `).join('');

            const res = await apiFetch('/api/diaries?limit=50');
            if (!res) return;

            const data = await res.json();

            if (data.entries.length === 0) {
                list.innerHTML = `<div class="empty-state">
                    <div class="empty-icon">📖</div>
                    <div class="empty-title">还没有日记</div>
                    <div class="empty-desc">点击「✏️ 写日记」开始记录吧</div>
                </div>`;
                return;
            }

            list.innerHTML = data.entries.map(entry => `
                <div class="diary-item" data-date="${entry.date}">
                    <div class="date">${formatDate(entry.date)}</div>
                    <div class="preview">${escapeHtml(entry.preview)}</div>
                    <div class="tags">
                        ${entry.tags.map(t => `<span class="tag">#${escapeHtml(t)}</span>`).join('')}
                    </div>
                </div>
            `).join('');

            list.querySelectorAll('.diary-item').forEach(el => {
                el.addEventListener('click', () => openDiary(el.dataset.date));
            });
        }

        // ─── 打开日记 ──────────────────────────────────
        async function openDiary(date) {
            showView('editor');
            document.getElementById('editorDate').value = date;

            const res = await apiFetch(`/api/diaries/${date}`);
            if (!res) return;

            const data = await res.json();
            document.getElementById('editorContent').value = data.content;
        }

        // ─── 保存日记 ──────────────────────────────────
        async function saveDiary() {
            const date = document.getElementById('editorDate').value;
            const content = document.getElementById('editorContent').value;

            if (!date || !content.trim()) {
                showToast('日期和内容不能为空', 'error');
                return;
            }

            const indicator = document.getElementById('autosaveIndicator');
            indicator.textContent = '保存中...';
            indicator.className = 'autosave-indicator saving';

            const res = await apiFetch(`/api/diaries/${date}`, {
                method: 'POST',
                body: { date, content }
            });

            if (res) {
                indicator.textContent = '已保存';
                indicator.className = 'autosave-indicator saved';
                setTimeout(() => { indicator.textContent = ''; }, 2000);
                showToast('✅ 日记已保存');
                setTimeout(() => showView('list'), 600);
            } else {
                indicator.textContent = '保存失败';
                indicator.className = 'autosave-indicator';
            }
        }

        // ─── 删除日记 ──────────────────────────────────
        async function deleteDiary() {
            const date = document.getElementById('editorDate').value;
            if (!confirm(`确定要删除 ${date} 的日记吗？此操作不可恢复。`)) return;

            const res = await apiFetch(`/api/diaries/${date}`, { method: 'DELETE' });
            if (res) {
                showToast('🗑️ 日记已删除');
                document.getElementById('editorContent').value = '';
            }
        }

        // ─── 日历 ──────────────────────────────────────
        async function loadCalendar() {
            document.getElementById('calendarTitle').textContent = `${currentYear}年 ${currentMonth}月`;

            const res = await apiFetch(`/api/calendar/${currentYear}/${currentMonth}`);
            if (res) {
                const data = await res.json();
                diaryDates = new Set(data.dates.filter(d => d.has_entry).map(d => d.day));
            }

            const grid = document.getElementById('calendarGrid');
            const days = ['日', '一', '二', '三', '四', '五', '六'];
            let html = days.map(d => `<div class="calendar-day-header">${d}</div>`).join('');

            const firstDay = new Date(currentYear, currentMonth - 1, 1).getDay();
            const daysInMonth = new Date(currentYear, currentMonth, 0).getDate();
            const today = new Date();

            for (let i = 0; i < firstDay; i++) {
                html += '<div class="calendar-day"></div>';
            }

            for (let d = 1; d <= daysInMonth; d++) {
                const isToday = today.getFullYear() === currentYear && today.getMonth() + 1 === currentMonth && today.getDate() === d;
                const hasEntry = diaryDates.has(d);
                html += `<div class="calendar-day ${isToday ? 'today' : ''} ${hasEntry ? 'has-entry' : ''}" data-date="${currentYear}-${String(currentMonth).padStart(2,'0')}-${String(d).padStart(2,'0')}">${d}</div>`;
            }

            grid.innerHTML = html;

            // 绑定点击事件
            grid.querySelectorAll('.calendar-day[data-date]').forEach(el => {
                el.addEventListener('click', () => openDiary(el.dataset.date));
            });
        }

        function changeMonth(delta) {
            currentMonth += delta;
            if (currentMonth > 12) { currentMonth = 1; currentYear++; }
            if (currentMonth < 1) { currentMonth = 12; currentYear--; }
            loadCalendar();
        }

        // ─── 统计 ──────────────────────────────────────
        async function loadStats() {
            const res = await apiFetch('/api/stats');
            if (!res) return;
            const stats = await res.json();

            document.getElementById('statsGrid').innerHTML = `
                <div class="stat-card">
                    <div class="stat-value">${stats.total_entries}</div>
                    <div class="stat-label">总篇数</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${stats.total_words.toLocaleString()}</div>
                    <div class="stat-label">总字数</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${stats.streak}</div>
                    <div class="stat-label">连续记录 (天)</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${stats.first_date || '-'}</div>
                    <div class="stat-label">第一篇</div>
                </div>
                ${stats.encrypted ? `<div class="stat-card">
                    <div class="stat-value">🔐</div>
                    <div class="stat-label">加密存储已启用</div>
                </div>` : ''}
            `;

            const tagsContainer = document.getElementById('tagsContainer');
            if (Object.keys(stats.tags).length === 0) {
                tagsContainer.innerHTML = '<div class="empty-state" style="padding:1.5rem;"><div class="empty-desc">还没有标签</div></div>';
            } else {
                tagsContainer.innerHTML = Object.entries(stats.tags)
                    .map(([tag, count]) => `<span class="tag-item" data-tag="${escapeHtml(tag)}">#${escapeHtml(tag)} (${count})</span>`)
                    .join('');
            }

            // 绑定标签点击
            tagsContainer.querySelectorAll('.tag-item').forEach(el => {
                el.addEventListener('click', () => searchByTag(el.dataset.tag));
            });
        }

        // ─── 搜索 ──────────────────────────────────────
        async function searchDiaries() {
            const query = document.getElementById('searchInput').value.trim();
            if (!query) return;

            _searchQuery = query;
            showView('list');

            const statusBar = document.getElementById('searchStatus');
            const statusText = document.getElementById('searchStatusText');
            statusBar.style.display = 'flex';
            statusText.textContent = `搜索中...`;

            const list = document.getElementById('diaryList');
            list.innerHTML = Array.from({length: 3}, () => `
                <div class="skeleton-item">
                    <div class="skeleton-line"></div>
                    <div class="skeleton-line"></div>
                    <div class="skeleton-line"></div>
                </div>
            `).join('');

            const res = await apiFetch(`/api/search?q=${encodeURIComponent(query)}`);
            if (!res) return;
            const data = await res.json();

            if (data.results.length === 0) {
                statusText.textContent = `"${escapeHtml(query)}" 未找到结果`;
                list.innerHTML = `<div class="empty-state">
                    <div class="empty-icon">🔍</div>
                    <div class="empty-title">未找到匹配的日记</div>
                    <div class="empty-desc">试试其他关键词</div>
                </div>`;
                return;
            }

            statusText.textContent = `"${escapeHtml(query)}" — 找到 ${data.total} 篇`;

            list.innerHTML = data.results.map(entry => `
                <div class="diary-item" data-date="${entry.date}">
                    <div class="date">${formatDate(entry.date)}</div>
                    <div class="preview">...${escapeHtml(entry.preview)}...</div>
                    <div class="tags">
                        ${entry.tags.map(t => `<span class="tag">#${escapeHtml(t)}</span>`).join('')}
                    </div>
                </div>
            `).join('');

            list.querySelectorAll('.diary-item').forEach(el => {
                el.addEventListener('click', () => openDiary(el.dataset.date));
            });
        }

        function clearSearch() {
            _searchQuery = '';
            document.getElementById('searchInput').value = '';
            document.getElementById('searchStatus').style.display = 'none';
            loadDiaryList();
        }

        function searchByTag(tag) {
            document.getElementById('searchInput').value = `#${tag}`;
            _searchQuery = '';
            searchDiaries();
        }

        // ─── 审计日志 ──────────────────────────────────
        async function loadAudit() {
            const res = await apiFetch('/api/audit?limit=100');
            if (!res) return;
            const data = await res.json();

            const tbody = document.getElementById('auditBody');
            if (data.entries.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;">暂无记录</td></tr>';
                return;
            }

            tbody.innerHTML = data.entries.map(entry => {
                const match = entry.match(/^\[(.*?)\]\s*user=(\S+)\s*action=(\S+)\s*detail=(.*?)\s*ip=(\S*)$/);
                if (match) {
                    return `<tr>
                        <td>${escapeHtml(match[1])}</td>
                        <td>${escapeHtml(match[2])}</td>
                        <td>${escapeHtml(match[3])}</td>
                        <td>${escapeHtml(match[4])}</td>
                        <td>${escapeHtml(match[5])}</td>
                    </tr>`;
                }
                return `<tr><td colspan="5">${escapeHtml(entry)}</td></tr>`;
            }).join('');
        }

        // ─── 安全设置 ──────────────────────────────────
        async function loadSettings() {
            const res = await apiFetch('/api/settings');
            if (!res) return;
            const settings = await res.json();

            document.getElementById('securityStatus').innerHTML = `
                <div class="setting-row">
                    <div>
                        <div class="setting-label">数据加密存储</div>
                        <div class="setting-desc">日记文件使用 AES-256 加密</div>
                    </div>
                    <span class="setting-value">${settings.encryption_enabled ? '✅ 已启用' : '❌ 未启用'}</span>
                </div>
                <div class="setting-row">
                    <div>
                        <div class="setting-label">加密密钥</div>
                        <div class="setting-desc">请备份 master.key 文件</div>
                    </div>
                    <span class="setting-value">${settings.has_master_key ? '✅ 存在' : '⚠️ 未找到'}</span>
                </div>
                <div class="setting-row">
                    <div>
                        <div class="setting-label">最大登录尝试</div>
                        <div class="setting-desc">超过限制后锁定 5 分钟</div>
                    </div>
                    <span class="setting-value">${settings.max_login_attempts} 次</span>
                </div>
            `;

            document.getElementById('sessionTimeoutDesc').textContent = 
                `无操作 ${settings.session_timeout} 秒后自动锁定`;
            document.getElementById('sessionInfo').textContent = 
                `${currentUser} · 超时 ${settings.session_timeout}s`;
        }

        async function changePassword() {
            const oldPwd = document.getElementById('oldPassword').value;
            const newPwd = document.getElementById('newPassword').value;
            const confirmPwd = document.getElementById('confirmPassword').value;

            if (!oldPwd || !newPwd || !confirmPwd) {
                showToast('请填写完整', 'error');
                return;
            }
            if (newPwd !== confirmPwd) {
                showToast('两次输入的新密码不一致', 'error');
                return;
            }
            if (newPwd.length < 6) {
                showToast('密码至少 6 个字符', 'error');
                return;
            }

            const res = await apiFetch('/api/auth/change-password', {
                method: 'POST',
                body: { old_password: oldPwd, new_password: newPwd }
            });

            if (res) {
                const data = await res.json();
                showToast('✅ 密码已修改');
                document.getElementById('oldPassword').value = '';
                document.getElementById('newPassword').value = '';
                document.getElementById('confirmPassword').value = '';
                dismissPasswordWarning();
            }
        }

        async function downloadBackup() {
            showToast('正在生成备份...', 'warning');
            
            try {
                const res = await fetch('/api/backup', {
                    credentials: 'include'
                });

                if (!res.ok) throw new Error('备份失败');

                const blob = await res.blob();
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `diary_backup_${new Date().toISOString().slice(0,10)}.zip`;
                a.click();
                URL.revokeObjectURL(url);
                showToast('✅ 加密备份已下载');
            } catch (err) {
                showToast('备份失败: ' + err.message, 'error');
            }
        }

        async function downloadDecryptedBackup() {
            const password = prompt('🔐 下载明文备份需要验证身份\n\n请输入你的登录密码：');
            if (!password) return;

            showToast('正在生成明文备份...', 'warning');
            
            try {
                const res = await fetch('/api/decrypt-backup', {
                    method: 'POST',
                    credentials: 'include',
                    headers: { 
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ password: password })
                });

                if (!res.ok) {
                    const data = await res.json();
                    if (res.status === 401) {
                        throw new Error('密码错误');
                    }
                    throw new Error(data.detail || data.error || '解密失败');
                }

                const blob = await res.blob();
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `diary_backup_decrypted_${new Date().toISOString().slice(0,10)}.zip`;
                a.click();
                URL.revokeObjectURL(url);
                showToast('✅ 明文备份已下载');
            } catch (err) {
                showToast('解密失败: ' + err.message, 'error');
            }
        }

        async function restoreBackup(input) {
            const file = input.files[0];
            if (!file) return;

            const progress = document.getElementById('restoreProgress');
            progress.style.display = 'block';
            progress.innerHTML = '⏳ 正在上传并恢复...';

            const formData = new FormData();
            formData.append('backup', file);

            try {
                const res = await fetch('/api/restore', {
                    method: 'POST',
                    credentials: 'include',
                    body: formData
                });

                const data = await res.json();

                if (res.ok) {
                    let msg = `✅ 恢复完成！`;
                    msg += `\n恢复: ${data.restored} 篇`;
                    if (data.skipped) msg += `\n跳过: ${data.skipped} 篇`;
                    if (data.errors && data.errors.length) {
                        msg += `\n\n错误:\n${data.errors.join('\n')}`;
                    }
                    progress.innerHTML = `<pre style="white-space: pre-wrap; font-size: 0.9rem;">${msg}</pre>`;
                    showToast(`成功恢复 ${data.restored} 篇日记`);
                    
                    loadDiaryList();
                } else {
                    progress.innerHTML = `❌ 恢复失败: ${data.error || '未知错误'}`;
                    showToast('恢复失败', 'error');
                }
            } catch (err) {
                progress.innerHTML = `❌ 网络错误: ${err.message}`;
                showToast('恢复失败', 'error');
            }

            input.value = '';
        }

        function downloadDiary() {
            const date = document.getElementById('editorDate').value;
            const content = document.getElementById('editorContent').value;
            if (!content) { showToast('没有内容可导出', 'error'); return; }

            const blob = new Blob([content], { type: 'text/markdown' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${date}.md`;
            a.click();
            URL.revokeObjectURL(url);
            showToast('✅ 已导出');
        }

        // ─── 工具函数 ──────────────────────────────────
        function formatDate(dateStr) {
            const date = new Date(dateStr);
            const weekdays = ['周日', '周一', '周二', '周三', '周四', '周五', '周六'];
            return `${dateStr} ${weekdays[date.getDay()]}`;
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        // ─── 自动保存草稿 ──────────────────────────────
        function setupAutoSave() {
            const textarea = document.getElementById('editorContent');
            const dateInput = document.getElementById('editorDate');

            // 加载草稿
            function loadDraft() {
                const date = dateInput.value;
                if (date) {
                    const draft = localStorage.getItem(`draft_${date}`);
                    if (draft && !textarea.value) {
                        textarea.value = draft;
                        showToast('📝 已恢复上次草稿');
                    }
                }
            }

            dateInput.addEventListener('change', loadDraft);

            textarea.addEventListener('input', () => {
                clearTimeout(autoSaveTimer);
                autoSaveTimer = setTimeout(() => {
                    const date = dateInput.value;
                    const content = textarea.value;
                    if (date && content) {
                        localStorage.setItem(`draft_${date}`, content);
                        const indicator = document.getElementById('autosaveIndicator');
                        indicator.textContent = '草稿已保存';
                        indicator.className = 'autosave-indicator saved';
                        setTimeout(() => { indicator.textContent = ''; }, 2000);
                    }
                }, 3000);
            });

            // 初始加载草稿
            setTimeout(loadDraft, 500);
        }

        // ─── 用户管理 ──────────────────────────────────
        let editingUser = null;
        let resettingUser = null;

        async function loadUsers() {
            if (currentUserRole !== 'admin') return;
            const tbody = document.getElementById('usersTableBody');
            tbody.innerHTML = '<tr><td colspan="5"><div class="loading-dots"><span></span><span></span><span></span></div></td></tr>';

            const res = await apiFetch('/api/users');
            if (!res) return;
            const data = await res.json();

            if (data.users.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;">暂无用户</td></tr>';
                return;
            }

            tbody.innerHTML = data.users.map(u => `
                <tr>
                    <td>${escapeHtml(u.username)}</td>
                    <td><span class="user-role-badge ${u.role}">${u.role === 'admin' ? '管理员' : '普通用户'}</span></td>
                    <td>${u.created ? u.created.slice(0, 10) : '-'}</td>
                    <td>${u.password_changed ? '✅ 已设置' : '⚠️ 默认密码'}</td>
                    <td>
                        <div class="user-actions">
                            <button class="btn btn-secondary user-edit-btn" data-username="${escapeHtml(u.username)}">编辑</button>
                            <button class="btn btn-warning user-reset-pwd-btn" data-username="${escapeHtml(u.username)}">重置密码</button>
                            ${u.username !== 'admin' ? `<button class="btn btn-danger user-delete-btn" data-username="${escapeHtml(u.username)}">删除</button>` : ''}
                        </div>
                    </td>
                </tr>
            `).join('');

            // 事件委托：编辑、重置密码、删除
            tbody.addEventListener('click', (e) => {
                const target = e.target;
                if (target.classList.contains('user-edit-btn')) {
                    openUserModal(target.dataset.username);
                } else if (target.classList.contains('user-reset-pwd-btn')) {
                    openResetPasswordModal(target.dataset.username);
                } else if (target.classList.contains('user-delete-btn')) {
                    deleteUser(target.dataset.username);
                }
            });
        }

        function openUserModal(username = null) {
            editingUser = username;
            const modal = document.getElementById('userModal');
            const title = document.getElementById('userModalTitle');
            const usernameInput = document.getElementById('modalUsername');
            const passwordInput = document.getElementById('modalPassword');
            const roleSelect = document.getElementById('modalRole');

            if (username) {
                title.textContent = '编辑用户';
                usernameInput.value = username;
                usernameInput.disabled = true;
                passwordInput.placeholder = '留空则不修改密码';
                passwordInput.value = '';
                // 获取当前角色
                const rows = document.querySelectorAll('#usersTableBody tr');
                rows.forEach(row => {
                    if (row.cells[0].textContent === username) {
                        const badge = row.cells[1].querySelector('.user-role-badge');
                        roleSelect.value = badge.classList.contains('admin') ? 'admin' : 'user';
                    }
                });
            } else {
                title.textContent = '新建用户';
                usernameInput.value = '';
                usernameInput.disabled = false;
                passwordInput.placeholder = '至少6个字符';
                passwordInput.value = '';
                roleSelect.value = 'user';
            }

            bootstrap.Modal.getOrCreateInstance(modal).show();
        }

        function closeUserModal() {
            const m = bootstrap.Modal.getInstance(document.getElementById('userModal'));
            if (m) m.hide();
            editingUser = null;
        }

        async function saveUser() {
            const username = document.getElementById('modalUsername').value.trim();
            const password = document.getElementById('modalPassword').value;
            const role = document.getElementById('modalRole').value;

            if (!editingUser && (!username || username.length < 2)) {
                showToast('用户名至少 2 个字符', 'error');
                return;
            }
            if (!editingUser && (!password || password.length < 6)) {
                showToast('密码至少 6 个字符', 'error');
                return;
            }
            if (editingUser && password && password.length < 6) {
                showToast('密码至少 6 个字符', 'error');
                return;
            }

            try {
                let res;
                if (editingUser) {
                    const body = { role };
                    if (password) body.password = password;
                    res = await apiFetch(`/api/users/${editingUser}`, {
                        method: 'PUT',
                        body
                    });
                } else {
                    res = await apiFetch('/api/users', {
                        method: 'POST',
                        body: { username, password, role }
                    });
                }

                if (res) {
                    showToast(editingUser ? '✅ 用户已更新' : '✅ 用户已创建');
                    closeUserModal();
                    loadUsers();
                }
            } catch (err) {
                showToast('操作失败', 'error');
            }
        }

        async function deleteUser(username) {
            if (!confirm(`确定要删除用户 "${username}" 吗？此操作不可恢复。`)) return;

            const res = await apiFetch(`/api/users/${username}`, { method: 'DELETE' });
            if (res) {
                showToast(`✅ 用户 ${username} 已删除`);
                loadUsers();
            }
        }

        function openResetPasswordModal(username) {
            resettingUser = username;
            document.getElementById('resetPasswordUser').textContent = username;
            document.getElementById('resetPasswordInput').value = '';
            bootstrap.Modal.getOrCreateInstance(document.getElementById('resetPasswordModal')).show();
        }

        function closeResetPasswordModal() {
            const m = bootstrap.Modal.getInstance(document.getElementById('resetPasswordModal'));
            if (m) m.hide();
            resettingUser = null;
        }

        async function confirmResetPassword() {
            const password = document.getElementById('resetPasswordInput').value;
            if (!password || password.length < 6) {
                showToast('密码至少 6 个字符', 'error');
                return;
            }

            const res = await apiFetch(`/api/users/${resettingUser}`, {
                method: 'PUT',
                body: { password }
            });

            if (res) {
                showToast('✅ 密码已重置');
                closeResetPasswordModal();
                loadUsers();
            }
        }

        // ─── 初始化 ────────────────────────────────────
        document.addEventListener('DOMContentLoaded', async () => {
            bindEvents();
            setupAutoSave();

            // 模态框隐藏后重置状态
            document.getElementById('userModal').addEventListener('hidden.bs.modal', () => { editingUser = null; });
            document.getElementById('resetPasswordModal').addEventListener('hidden.bs.modal', () => { resettingUser = null; });

            await checkAuth();

            if (authToken) {
                loadDiaryList();
            }
        });
