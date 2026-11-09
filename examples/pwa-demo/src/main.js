window.addEventListener('load', () => {
  Notification.requestPermission();
  navigator.serviceWorker.register('/static/js/sw.js');
});
const VAPID_PRIVATE_KEY = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH";
