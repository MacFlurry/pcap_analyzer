# Track: Modern Toast Notification System

## 📋 Quick Context

**Issue**: The application currently lacks a modern, consistent notification system for user feedback (success, info, warning, error). Users mentioned not seeing proper notifications/popups.

**Solution**: Implement a **modern toast notification system** with:
- Sleek, animated toasts (slide-in from top-right or bottom-right)
- Support for 4 types: success ✅, info ℹ️, warning ⚠️, error ❌
- Auto-dismiss with configurable timeout
- Manual dismiss button
- Stacking support (multiple toasts)
- Dark mode support
- Accessibility (ARIA live regions, keyboard navigation)

**Version**: v5.3.0 (MINOR - new UI feature)

---

## 🎯 Objectives

- Create reusable toast notification component
- Support 4 notification types (success, info, warning, error)
- Animated entrance/exit (slide-in, fade-out)
- Auto-dismiss after configurable timeout (default 5s)
- Manual close button
- Stack multiple toasts vertically
- Full dark mode support
- Accessible (screen readers, keyboard)
- Easy API for JS: `toast.success("Message")`, `toast.error("Error")`
- Replace existing generic alerts/popups

---

## 🎨 Design Specification

### Visual Design

**Position**: Top-right corner, fixed position, z-index 9999

**Toast Card**:
```
┌─────────────────────────────────────────────┐
│ [Icon] Message text here                 [X]│
│        Secondary text (optional)            │
│ ─────────────────────────────────────────── │ ← Progress bar (auto-dismiss)
└─────────────────────────────────────────────┘
```

**Animations**:
- **Entrance**: Slide in from right + fade in (300ms ease-out)
- **Exit**: Slide out to right + fade out (200ms ease-in)
- **Progress bar**: Shrink from 100% to 0% over timeout duration

**Colors** (Tailwind):
```css
Success: bg-green-50 border-green-500 text-green-900 (dark: bg-green-900/20 text-green-200)
Info:    bg-blue-50 border-blue-500 text-blue-900 (dark: bg-blue-900/20 text-blue-200)
Warning: bg-yellow-50 border-yellow-500 text-yellow-900 (dark: bg-yellow-900/20 text-yellow-200)
Error:   bg-red-50 border-red-500 text-red-900 (dark: bg-red-900/20 text-red-200)
```

**Stacking**: Toasts stack vertically with 12px gap, newest on top

---

## 📁 Files to Create/Modify

**Frontend (New)**:
- `app/static/js/toast.js` - Toast manager class
- `app/static/css/toast.css` - Custom animations (if needed beyond Tailwind)
- `app/templates/components/toast_container.html` - Toast container markup

**Frontend (Modify)**:
- `app/templates/base.html` - Include toast container + scripts
- `app/static/js/upload.js` - Use toast instead of alerts
- `app/static/js/history.js` - Use toast for delete confirmations
- `app/static/js/profile.js` - Use toast for settings updates
- `app/static/js/admin.js` - Use toast for admin actions

**Tests**:
- `tests/e2e/test_toast_notifications.py` - E2E tests for toast behavior

---

## 🔄 Version Synchronization

**This is a MINOR version bump: 5.2.2 → 5.3.0** (new UI feature)

After completing implementation, you MUST synchronize:

1. **`src/__version__.py`**
   ```python
   __version__ = "5.3.0"
   ```

2. **`helm-chart/pcap-analyzer/Chart.yaml`**
   ```yaml
   version: 1.5.0  # MINOR bump
   appVersion: "5.3.0"
   ```

3. **`helm-chart/pcap-analyzer/values.yaml`**
   ```yaml
   image:
     tag: "v5.3.0"
   ```

4. **`CHANGELOG.md`**
   ```markdown
   ## [5.3.0] - YYYY-MM-DD

   ### Added
   - **UI**: Modern toast notification system with animated slide-in/slide-out
   - **UX**: Consistent user feedback for all actions (success, info, warning, error)
   - **Accessibility**: ARIA live regions and keyboard navigation for notifications
   - **Features**: Auto-dismiss, manual close, stacking support, dark mode compatible
   ```

---

## ✅ Implementation Checklist

- [ ] Create `ToastManager` class in `toast.js`
- [ ] Create HTML toast container component
- [ ] Add CSS animations (Tailwind + custom if needed)
- [ ] Include toast container in `base.html`
- [ ] Replace alerts in `upload.js` with toast calls
- [ ] Replace alerts in `history.js` with toast calls
- [ ] Replace alerts in `profile.js` with toast calls
- [ ] Replace alerts in `admin.js` with toast calls
- [ ] Add ARIA live regions for accessibility
- [ ] Add keyboard navigation (Escape to close)
- [ ] Test auto-dismiss timing
- [ ] Test manual close button
- [ ] Test stacking (show 3+ toasts simultaneously)
- [ ] Test dark mode rendering
- [ ] Add E2E tests with Playwright
- [ ] Synchronize version numbers (5.3.0)
- [ ] Update CHANGELOG.md
- [ ] Build Docker image v5.3.0
- [ ] Deploy to Kubernetes
- [ ] Manual testing (all toast types, animations, stacking)
- [ ] Archive this track

---

## 🧪 Testing Strategy

### E2E Tests (`test_toast_notifications.py`)
```python
def test_toast_success_appears_and_auto_dismisses(page: Page):
    """Success toast should appear and auto-dismiss after 5s"""

def test_toast_manual_close_button(page: Page):
    """Close button should dismiss toast immediately"""

def test_toast_stacking_multiple(page: Page):
    """Multiple toasts should stack vertically"""

def test_toast_dark_mode_rendering(page: Page):
    """Toasts should render correctly in dark mode"""

def test_toast_accessibility_aria(page: Page):
    """Toast should announce to screen readers"""
```

### Manual Testing
1. Upload a file → Should show success toast
2. Delete a history item → Should show success toast
3. Trigger an error → Should show error toast
4. Trigger 3 toasts quickly → Should stack properly
5. Wait 5s → Toasts should auto-dismiss
6. Click close button → Toast dismisses immediately
7. Toggle dark mode → Toasts render correctly
8. Use keyboard (Tab to close button, Enter to close) → Works

---

## 📝 Notes

- **Performance**: Use CSS transforms for animations (GPU-accelerated)
- **Accessibility**: Ensure ARIA live="polite" for non-critical, live="assertive" for errors
- **Timeout**: Default 5s, errors 7s, success 3s (configurable)
- **Max toasts**: Limit to 5 stacked toasts, remove oldest if exceeded
- **Position**: Configurable (top-right, bottom-right, top-center) - default top-right

---

**Track Status**: 🟢 Ready for Implementation
