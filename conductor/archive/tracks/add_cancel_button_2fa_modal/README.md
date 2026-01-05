# Track: Add Cancel Button to 2FA Setup Modal

## 📋 Quick Context

**Issue**: The 2FA setup modal only has an "Activate" button. If a user wants to postpone activation, the only way is to reload the page - poor UX.

**Solution**: Add a "Cancel" / "Fermer" button to allow users to close the modal without reloading.

**Version**: v5.2.1 (PATCH - UX bugfix)

---

## 🎯 Objectives

- Add a "Cancel" button in the 2FA setup modal
- Clicking "Cancel" should close the modal and return to the profile page
- Maintain visual consistency with the rest of the application

---

## 📁 Files to Modify

- `app/templates/profile.html` - Add cancel button in 2FA modal form
- `app/static/js/profile.js` - Add event handler for cancel button
- *(Optional)* `tests/e2e/test_2fa_setup.py` - Add test for cancel functionality

---

## 🔄 Version Synchronization (CRITICAL)

**This is a PATCH version bump: 5.2.0 → 5.2.1**

After completing implementation, you MUST synchronize these files:

### Required Changes:
1. **`src/__version__.py`**
   ```python
   __version__ = "5.2.1"
   ```

2. **`helm-chart/pcap-analyzer/Chart.yaml`**
   ```yaml
   version: 1.4.1  # Helm chart version bump
   appVersion: "5.2.1"
   ```

3. **`helm-chart/pcap-analyzer/values.yaml`**
   ```yaml
   image:
     tag: "v5.2.1"
   ```

4. **`CHANGELOG.md`**
   ```markdown
   ## [5.2.1] - YYYY-MM-DD

   ### Fixed
   - **UX**: Added "Cancel" button in 2FA setup modal to allow postponing activation without page reload
   ```

---

## ✅ Implementation Checklist

- [ ] Add "Cancel" button in `app/templates/profile.html`
- [ ] Implement cancel logic in `app/static/js/profile.js`
- [ ] Test manually: click cancel closes modal without activating 2FA
- [ ] (Optional) Add E2E test for cancel button
- [ ] Synchronize version numbers (see above)
- [ ] Update CHANGELOG.md
- [ ] Test deployment in Kubernetes
- [ ] Archive this track to `conductor/archive/tracks/add_cancel_button_2fa_modal/`

---

## 🧪 Testing

**Manual Testing:**
1. Login as a user
2. Go to Profile page
3. Click "Activer 2FA" button
4. Modal opens with QR code
5. Click "Cancel" button → Modal should close, no 2FA activation
6. Re-open modal → Should work normally

**Expected Behavior:**
- Cancel button closes the modal
- No API call to activate 2FA
- User can re-open the modal later
- No page reload needed

---

## 📝 Notes

- This is a small UX improvement, hence PATCH version
- The cancel button should have a secondary/neutral style (not primary blue)
- Consider using the same modal close mechanism as other modals in the app

---

**Track Status**: 🟢 Ready for Implementation
