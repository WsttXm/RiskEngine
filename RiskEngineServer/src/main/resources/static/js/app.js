document.addEventListener('DOMContentLoaded', function() {
    // 确认操作
    document.querySelectorAll('[data-confirm]').forEach(function(el) {
        el.addEventListener('click', function(e) {
            if (!confirm(el.getAttribute('data-confirm'))) {
                e.preventDefault();
            }
        });
    });

    // JSON格式化显示
    document.querySelectorAll('.json-raw').forEach(function(el) {
        try {
            var json = JSON.parse(el.textContent);
            el.textContent = JSON.stringify(json, null, 2);
        } catch (e) {
            // 非JSON内容保持原样
        }
    });

    // 复制到剪贴板
    document.querySelectorAll('.btn-copy').forEach(function(btn) {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            var text;
            var fromId = btn.getAttribute('data-copy-from');
            if (fromId) {
                text = document.getElementById(fromId).textContent;
            } else {
                text = btn.getAttribute('data-copy');
            }
            if (!text) return;
            navigator.clipboard.writeText(text).then(function() {
                btn.classList.add('copied');
                var origHTML = btn.innerHTML;
                btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>';
                setTimeout(function() {
                    btn.innerHTML = origHTML;
                    btn.classList.remove('copied');
                }, 1500);
            });
        });
    });

    // SDK 集成代码 - 选择应用后填充 App Key 和加密密钥
    var sdkSelect = document.getElementById('sdkAppSelect');
    if (sdkSelect) {
        sdkSelect.addEventListener('change', function() {
            var opt = sdkSelect.options[sdkSelect.selectedIndex];
            var appKey = opt.value;
            var encKey = opt.getAttribute('data-encryption-key');
            var appKeySpan = document.getElementById('sdkAppKey');
            var encKeySpan = document.getElementById('sdkEncKey');
            if (appKeySpan) appKeySpan.textContent = appKey;
            if (encKeySpan) encKeySpan.textContent = encKey;
        });
    }

    // 侧边栏 toggle (移动端)
    var sidebar = document.getElementById('sidebar');
    var overlay = document.getElementById('sidebarOverlay');
    var toggle = document.getElementById('sidebarToggle');

    if (toggle && sidebar && overlay) {
        toggle.addEventListener('click', function() {
            sidebar.classList.toggle('show');
            overlay.classList.toggle('show');
        });
        overlay.addEventListener('click', function() {
            sidebar.classList.remove('show');
            overlay.classList.remove('show');
        });
    }
});
