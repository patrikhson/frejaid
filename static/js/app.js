// app.js — loaded on every page

// Register service worker (PWA)
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/static/sw.js').catch(console.error);
}

// GPS capture for check-in form
// Populates hidden fields submission_lat, submission_lng, submission_accuracy
document.addEventListener('DOMContentLoaded', () => {
  const latField = document.getElementById('submission_lat');
  const lngField = document.getElementById('submission_lng');
  const accField = document.getElementById('submission_accuracy');
  const gpsStatus = document.getElementById('gps_status');

  if (latField && navigator.geolocation) {
    if (gpsStatus) gpsStatus.textContent = 'Acquiring GPS…';
    navigator.geolocation.getCurrentPosition(
      (pos) => {
        latField.value = pos.coords.latitude;
        lngField.value = pos.coords.longitude;
        if (accField) accField.value = pos.coords.accuracy;
        if (gpsStatus) gpsStatus.textContent = `GPS: ±${Math.round(pos.coords.accuracy)}m`;
      },
      () => {
        if (gpsStatus) gpsStatus.textContent = 'GPS unavailable';
      },
      { enableHighAccuracy: true, timeout: 10000 }
    );
  }
});
