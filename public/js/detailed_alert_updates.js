console.log('detailed_alert_updates.js: Script loaded at', new Date().toISOString());

(function () {
  // Fallback toast function using #messageOverlay
  function showToast(message, type = 'info') {
    console.log(`detailed_alert_updates.js: Toast [${type}]: ${message}`);
    const overlay = document.getElementById('messageOverlay');
    if (window.toastr) {
      window.toastr.options = {
        positionClass: 'toast-center-center',
        timeOut: 5000,
        closeButton: true,
        progressBar: true
      };
      if (type === 'success') window.toastr.success(message);
      else if (type === 'error') window.toastr.error(message);
      else window.toastr.info(message);
    } else if (overlay) {
      overlay.textContent = message;
      overlay.style.display = 'block';
      overlay.style.background = type === 'error' ? 'rgba(255, 0, 0, 0.8)' : 'rgba(0, 128, 0, 0.8)';
      overlay.style.color = '#fff';
      overlay.style.padding = '10px 20px';
      overlay.style.borderRadius = '5px';
      overlay.style.fontSize = '16px';
      overlay.style.zIndex = '1003';
      setTimeout(() => { overlay.style.display = 'none'; }, 5000);
    } else {
      console.warn('detailed_alert_updates.js: No toastr or messageOverlay, using alert');
      alert(message);
    }
  }

  // Initialize after DOM and map are ready
  function initialize(attempt = 1, maxAttempts = 10) {
    console.log(`detailed_alert_updates.js: Initializing (attempt ${attempt}/${maxAttempts})`);

    // DOM elements
    const detailedAlertBtn = document.getElementById('detailedAlert-btn');
    const detailedAlertBox = document.getElementById('detailedAlertBox');
    const clickToAlertBtn = document.getElementById('clickToAlertBtn');
    const alertAtMyLocationBtn = document.getElementById('alertAtMyLocationBtn');
    const alertForm = document.getElementById('alertForm');
    const selectedLocation = document.getElementById('selectedLocation');
    const postNotes = document.getElementById('postNotes');
    const postAlertBtn = document.getElementById('postAlertBtn');
    const closePostBtn = document.getElementById('closePostBtn');
    const closeBtn = detailedAlertBox ? detailedAlertBox.querySelector('.close-btn') : null;

    // Check DOM elements
    if (!detailedAlertBtn || !detailedAlertBox || !clickToAlertBtn || !alertAtMyLocationBtn || !alertForm || !selectedLocation || !postNotes || !postAlertBtn || !closePostBtn || !closeBtn) {
      console.error('detailed_alert_updates.js: Missing DOM elements', {
        detailedAlertBtn: !!detailedAlertBtn,
        detailedAlertBox: !!detailedAlertBox,
        clickToAlertBtn: !!clickToAlertBtn,
        alertAtMyLocationBtn: !!alertAtMyLocationBtn,
        alertForm: !!alertForm,
        selectedLocation: !!selectedLocation,
        postNotes: !!postNotes,
        postAlertBtn: !!postAlertBtn,
        closePostBtn: !!closePostBtn,
        closeBtn: !!closeBtn
      });
      if (attempt < maxAttempts) {
        console.warn('detailed_alert_updates.js: Retrying initialization in 1s');
        setTimeout(() => initialize(attempt + 1, maxAttempts), 1000);
      } else {
        console.error('detailed_alert_updates.js: Max initialization attempts reached');
      }
      return;
    }

    // Check Google Maps
    if (!window.google || !window.google.maps || !window.map) {
      console.warn('detailed_alert_updates.js: Google Maps not initialized. Retrying in 1s');
      if (attempt < maxAttempts) {
        setTimeout(() => initialize(attempt + 1, maxAttempts), 1000);
      } else {
        console.error('detailed_alert_updates.js: Max initialization attempts reached for Google Maps');
      }
      return;
    }

    const map = window.map;

    // Check Socket.IO (optional, won't block initialization)
    if (!window.socket) {
      console.warn('detailed_alert_updates.js: Socket.IO not initialized, alerts will not be sent to server');
    }

    function showDetailedAlertHUD() {
      console.log('detailed_alert_updates.js: Opening Detailed Alert HUD');
      detailedAlertBox.classList.add('active');
      alertForm.style.display = 'none';
      document.getElementById('alertOptions').style.display = 'block';
      selectedLocation.textContent = 'N/A';
      postNotes.value = '';
    }

    function handleLocationAlert() {
      console.log('detailed_alert_updates.js: Click/Press location to alert clicked');
      detailedAlertBox.classList.remove('active');
      showToast('Waiting for click or press a location on the map');

      const clickListener = window.google.maps.event.addListener(map, 'click', (e) => {
        console.log('detailed_alert_updates.js: Map clicked at:', e.latLng);
        const lat = e.latLng.lat();
        const lng = e.latLng.lng();
        window.google.maps.event.removeListener(clickListener);
        showDetailedAlertForm(lat, lng);
      });
    }

    function showDetailedAlertForm(lat, lng) {
      console.log('detailed_alert_updates.js: Showing alert form with location:', { lat, lng });
      detailedAlertBox.classList.add('active');
      alertForm.style.display = 'block';
      document.getElementById('alertOptions').style.display = 'none';
      selectedLocation.textContent = `(${lat.toFixed(4)}, ${lng.toFixed(4)})`;
    }

    function handleCurrentLocationAlert() {
      console.log('detailed_alert_updates.js: Alert at current location clicked');
      detailedAlertBox.classList.remove('active');
      navigator.geolocation.getCurrentPosition(
        (position) => {
          const { latitude, longitude } = position.coords;
          console.log('detailed_alert_updates.js: Current location:', { latitude, longitude });
          addMarker(latitude, longitude, '');
          showToast('Your alert has been posted', 'success');
        },
        (error) => {
          console.error('detailed_alert_updates.js: Geolocation error:', error);
          showToast('Unable to get current location', 'error');
        }
      );
    }

    function addMarker(lat, lng, notes) {
      console.log('detailed_alert_updates.js: Adding marker at:', { lat, lng, notes });
      const marker = new window.google.maps.Marker({
        position: { lat, lng },
        map: map,
        title: notes || 'Alert'
      });
      if (window.socket) {
        window.socket.emit('detailedAlert', { lat, lng, notes });
        console.log('detailed_alert_updates.js: Emitted detailedAlert via Socket.IO');
      } else {
        console.warn('detailed_alert_updates.js: Socket.IO not available, marker added locally');
      }
    }

    // Attach event listeners
    detailedAlertBtn.addEventListener('click', () => {
      console.log('detailed_alert_updates.js: Detailed Alert button clicked');
      showDetailedAlertHUD();
    });
    clickToAlertBtn.addEventListener('click', () => {
      console.log('detailed_alert_updates.js: Click to Alert button clicked');
      handleLocationAlert();
    });
    alertAtMyLocationBtn.addEventListener('click', () => {
      console.log('detailed_alert_updates.js: Alert at My Location button clicked');
      handleCurrentLocationAlert();
    });
    postAlertBtn.addEventListener('click', () => {
      console.log('detailed_alert_updates.js: Post Alert button clicked');
      const latLng = selectedLocation.textContent.match(/([-.\d]+),\s*([-.\d]+)/);
      if (latLng) {
        const lat = parseFloat(latLng[1]);
        const lng = parseFloat(latLng[2]);
        addMarker(lat, lng, postNotes.value);
        detailedAlertBox.classList.remove('active');
        showToast('Your alert has been posted', 'success');
      } else {
        console.error('detailed_alert_updates.js: Invalid location format:', selectedLocation.textContent);
        showToast('Failed to post alert: invalid location', 'error');
      }
    });
    closePostBtn.addEventListener('click', () => {
      console.log('detailed_alert_updates.js: Cancel Post button clicked');
      detailedAlertBox.classList.remove('active');
    });
    closeBtn.addEventListener('click', () => {
      console.log('detailed_alert_updates.js: Close HUD button clicked');
      detailedAlertBox.classList.remove('active');
    });

    console.log('detailed_alert_updates.js: Event listeners attached successfully at', new Date().toISOString());
  }

  // Run initialization when DOM is ready
  if (document.readyState === 'loading') {
    console.log('detailed_alert_updates.js: Waiting for DOMContentLoaded');
    document.addEventListener('DOMContentLoaded', () => initialize());
  } else {
    console.log('detailed_alert_updates.js: DOM already loaded, initializing');
    initialize();
  }
})();