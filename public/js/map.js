document.addEventListener('DOMContentLoaded', () => {
  console.time('DOM initialization');
  const BASE_URL = 'http://localhost:3000';
  let map, directionsService, directionsRenderer, autocompleteService, socket, userMarker;
  let currentUser = null;
  let userProfile = null;
  let isMuted = false;
  let isSelectingLocation = false;
  let currentHazards = [];
  let currentPage = 1;
  const alertsPerPage = 5;
  let alerts = [];

  const loginScreen = document.getElementById('login-screen');
  const loginUsername = document.getElementById('login-username');
  const loginPassword = document.getElementById('login-password');
  const loginBtn = document.getElementById('login-btn');
  const navAddress = document.getElementById('navAddress');
  const suggestions = document.getElementById('suggestions');
  const navOverlay = document.getElementById('navOverlay');
  const closeOverlay = document.getElementById('closeOverlay');
  const cancelBtn = document.getElementById('cancel-btn');
  const recenterBtn = document.getElementById('recenter-btn');
  const muteBtn = document.getElementById('mute-btn');
  const hazardBtn = document.getElementById('hazard-btn');
  const micButton = document.getElementById('mic-button');
  const voiceOverlay = document.getElementById('voiceOverlay');
  const closeVoiceOverlay = document.getElementById('closeVoiceOverlay');
  const detailedAlertBtn = document.getElementById('detailedAlert-btn');
  const detailedAlertBox = document.getElementById('detailedAlertBox');
  const closeDetailedAlertBtn = document.getElementById('detailedAlertBox').querySelector('.close-btn');
  const clickLocationBtn = document.getElementById('click-location-alert');
  const alertCurrentBtn = document.getElementById('alert-current-location');
  const postAlertBtn = document.getElementById('post-alert');
  const cancelAlertBtn = document.getElementById('cancel-alert');
  const locationDisplay = document.getElementById('location-display');
  const selectedLocation = document.getElementById('selected-location');
  const alertType = document.getElementById('alertType');
  const alertNotes = document.getElementById('alertNotes');
  const profileBtn = document.getElementById('profile-btn');
  const profileHud = document.getElementById('profile-hud');
  const closeBtn = profileHud.querySelector('.close-btn');
  const tabButtons = profileHud.querySelectorAll('.tab-button');
  const accountInfo = profileHud.querySelector('.account-info');
  const editProfile = profileHud.querySelector('.edit-profile');
  const alertsTab = profileHud.querySelector('.alerts');
  const alertTable = document.getElementById('alert-table');
  const alertPagination = document.getElementById('alert-pagination');
  const saveProfileBtn = document.getElementById('save-profile-btn');
  const settingsBtn = document.getElementById('settings-btn');
  const settingsHud = document.getElementById('settings-hud');
  const closeSettings = document.getElementById('closeSettings');
  const rerouteYes = document.getElementById('rerouteYes');
  const rerouteNo = document.getElementById('rerouteNo');
  const addAlertBtn = document.getElementById('addAlert');

  let currentTab = 'account';

  function initMap() {
    map = new google.maps.Map(document.getElementById('map'), {
      center: { lat: 37.7749, lng: -122.4194 },
      zoom: 12,
      gestureHandling: 'greedy',
      disableDefaultUI: true,
    });
    directionsService = new google.maps.DirectionsService();
    directionsRenderer = new google.maps.DirectionsRenderer({ map });
    autocompleteService = new google.maps.places.AutocompleteService();
    initSocket();
    initGeolocation();
    if (localStorage.getItem('token')) {
      fetchUserProfile();
    }
  }

  function initSocket() {
    socket = io(BASE_URL);
    socket.on('connect', () => console.log('Socket connected'));
    socket.on('newAlert', (alert) => {
      addMarker(alert);
      alerts.push(alert);
      if (currentTab === 'alerts') {
        updateAlertTable();
      }
    });
    socket.on('removeAlert', (alertId) => {
      alerts = alerts.filter(alert => alert._id !== alertId);
      if (currentTab === 'alerts') {
        updateAlertTable();
      }
    });
  }

  function initGeolocation() {
    if (navigator.geolocation) {
      navigator.geolocation.watchPosition(
        (position) => {
          const pos = {
            lat: position.coords.latitude,
            lng: position.coords.longitude,
          };
          if (!userMarker) {
            userMarker = new google.maps.Marker({
              position: pos,
              map,
              title: 'Your Location',
            });
            map.setCenter(pos);
          } else {
            userMarker.setPosition(pos);
          }
        },
        (error) => console.error('Geolocation error:', error),
        { enableHighAccuracy: true, timeout: 5000, maximumAge: 0 }
      );
    }
  }

  async function fetchWithTokenRefresh(url, options) {
    let token = localStorage.getItem('token');
    options.headers = options.headers || {};
    options.headers['Authorization'] = `Bearer ${token}`;
    let response = await fetch(url, options);
    if (response.status === 401) {
      const refreshResponse = await fetch(`${BASE_URL}/api/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken: localStorage.getItem('refreshToken') }),
      });
      if (refreshResponse.ok) {
        const data = await refreshResponse.json();
        localStorage.setItem('token', data.accessToken);
        options.headers['Authorization'] = `Bearer ${data.accessToken}`;
        response = await fetch(url, options);
      } else {
        logout();
      }
    }
    return response;
  }

  function login(username, password, loginBtn, loginUsername, loginPassword) {
    loginBtn.disabled = true;
    fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    })
      .then(response => {
        if (!response.ok) throw new Error('Login failed');
        return response.json();
      })
      .then(data => {
        localStorage.setItem('token', data.accessToken);
        localStorage.setItem('refreshToken', data.refreshToken);
        currentUser = { username: data.user.username, id: data.user._id };
        fetchUserProfile();
        loginScreen.style.display = 'none';
        document.getElementById('map').style.display = 'block';
        document.getElementById('nav-input').style.display = 'flex';
        document.getElementById('control-panel').style.display = 'flex';
        document.getElementById('tools-hud').style.display = 'flex';
      })
      .catch(err => {
        console.error('Login error:', err.message);
        showToastMessage('Login failed. Please check your credentials.', 7000, true);
        loginUsername.classList.add('invalid');
        loginPassword.classList.add('invalid');
      })
      .finally(() => {
        loginBtn.disabled = false;
      });
  }

  function fetchUserProfile() {
    fetchWithTokenRefresh(`${BASE_URL}/api/auth/me`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    })
      .then(response => response.json())
      .then(data => {
        userProfile = data;
        currentUser = { username: data.username, id: data._id };
        updateProfileDisplay();
        updateEditProfileForm();
        fetchAlerts();
      })
      .catch(err => {
        console.error('Fetch user profile error:', err.message);
        logout();
      });
  }

  function updateProfileDisplay() {
    document.getElementById('account-name').textContent = `Name: ${userProfile.name || 'N/A'}`;
    document.getElementById('account-username').textContent = `Username: ${userProfile.username || 'N/A'}`;
    document.getElementById('account-email').textContent = `Email: ${userProfile.email || 'N/A'}`;
    document.getElementById('account-age').textContent = `Age: ${userProfile.age || 'N/A'}`;
    document.getElementById('account-dob').textContent = `DOB: ${userProfile.dob || 'N/A'}`;
    document.getElementById('account-location').textContent = `Location: ${userProfile.location || 'N/A'}`;
  }

  function updateEditProfileForm() {
    document.getElementById('edit-name').value = userProfile.name || '';
    document.getElementById('edit-username').value = userProfile.username || '';
    document.getElementById('edit-email').value = userProfile.email || '';
    document.getElementById('edit-age').value = userProfile.age || '';
    document.getElementById('edit-dob').value = userProfile.dob || '';
    document.getElementById('edit-location').value = userProfile.location || '';
  }

  function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('refreshToken');
    currentUser = null;
    userProfile = null;
    loginScreen.style.display = 'flex';
    document.getElementById('map').style.display = 'none';
    document.getElementById('nav-input').style.display = 'none';
    document.getElementById('control-panel').style.display = 'none';
    document.getElementById('tools-hud').style.display = 'none';
    showToastMessage('Logged out successfully.', 5000);
  }

  function showOverlay() {
    navOverlay.style.display = 'flex';
  }

  function startNavigation(destination) {
    if (!destination) return;
    navigator.geolocation.getCurrentPosition((position) => {
      const origin = new google.maps.LatLng(position.coords.latitude, position.coords.longitude);
      directionsService.route({
        origin,
        destination,
        travelMode: google.maps.TravelMode.DRIVING,
      }, (result, status) => {
        if (status === google.maps.DirectionsStatus.OK) {
          directionsRenderer.setDirections(result);
          document.getElementById('hud').classList.add('navigating');
          document.getElementById('control-hud').classList.add('navigating');
        } else {
          console.error('Directions request failed:', status);
          showToastMessage('Failed to start navigation.', 7000, true);
        }
      });
    });
  }

  function stopNavigation() {
    directionsRenderer.setDirections(null);
    document.getElementById('hud').classList.remove('navigating');
    document.getElementById('control-hud').classList.remove('navigating');
    showToastMessage('Navigation stopped.', 5000);
  }

  function recenterMap() {
    if (userMarker) {
      map.setCenter(userMarker.getPosition());
      map.setZoom(15);
      showToastMessage('Map recentered to your location.', 5000);
    }
  }

  function startVoiceRecognition() {
    voiceOverlay.style.display = 'flex';
    const instruction = document.getElementById('voiceInstruction');
    const pulsator = voiceOverlay.querySelector('.pulsator');
    instruction.textContent = 'Speak the address or location...';
    pulsator.classList.add('active');
    setTimeout(() => {
      instruction.textContent = 'Processing...';
      setTimeout(() => {
        instruction.textContent = 'Destination set to: Sample Location';
        pulsator.classList.remove('active');
        startNavigation('Sample Location');
        voiceOverlay.style.display = 'none';
        showToastMessage('Voice navigation started.', 5000);
      }, 2000);
    }, 3000);
  }

  function stopVoiceRecognition() {
    voiceOverlay.querySelector('.pulsator').classList.remove('active');
    showToastMessage('Voice recognition stopped.', 5000);
  }

  function showDetailedAlertBox() {
    detailedAlertBox.classList.add('active');
    detailedAlertBox.style.display = 'flex';
    detailedAlertBox.style.opacity = '1';
    showToastMessage('Select alert type or location.', 5000);
  }

  function addHazardMarker() {
    if (!isSelectingLocation) {
      isSelectingLocation = true;
      showToastMessage('Click on the map to add a hazard.', 5000);
      const listener = map.addListener('click', (event) => {
        const lat = event.latLng.lat();
        const lng = event.latLng.lng();
        const alert = {
          type: 'Hazard',
          notes: '',
          location: { coordinates: [lng, lat] },
          userId: currentUser.id,
          username: currentUser.username,
        };
        addAlert(alert.type, alert.notes, event.latLng).then(() => {
          showToastMessage('Hazard added successfully.', 5000);
        }).catch(err => {
          showToastMessage(err.message || 'Failed to add hazard.', 7000, true);
        });
        google.maps.event.removeListener(listener);
        isSelectingLocation = false;
      });
    }
  }

  function addAlert(type, notes, position) {
    return new Promise((resolve, reject) => {
      const alert = {
        type,
        notes,
        location: { coordinates: [position.lng(), position.lat()] },
        userId: currentUser.id,
        username: currentUser.username,
      };
      fetchWithTokenRefresh(`${BASE_URL}/api/alerts`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(alert),
      })
        .then(response => {
          if (!response.ok) throw new Error('Failed to post alert');
          return response.json();
        })
        .then(data => {
          socket.emit('newAlert', data);
          addMarker(data);
          alerts.push(data);
          if (currentTab === 'alerts') {
            updateAlertTable();
          }
          resolve(data);
        })
        .catch(err => reject(err));
    });
  }

  function addMarker(alert) {
    const marker = new google.maps.Marker({
      position: { lat: alert.location.coordinates[1], lng: alert.location.coordinates[0] },
      map,
      title: alert.type,
      icon: {
        url: `http://maps.google.com/mapfiles/ms/icons/${alert.type.toLowerCase() === 'hazard' ? 'yellow' : 'red'}-dot.png`,
      },
    });
    marker.addListener('click', () => {
      showToastMessage(`${alert.type}: ${alert.notes || 'No notes'}`, 5000);
    });
  }

  function alertAtCurrentLocation() {
    navigator.geolocation.getCurrentPosition((position) => {
      const lat = position.coords.latitude;
      const lng = position.coords.longitude;
      if (selectedLocation) selectedLocation.textContent = `${lat.toFixed(6)}, ${lng.toFixed(6)}`;
      if (detailedAlertBox) {
        detailedAlertBox.classList.add('active');
        detailedAlertBox.style.display = 'flex';
        detailedAlertBox.style.left = '50%';
        detailedAlertBox.style.top = '50%';
        detailedAlertBox.style.transform = 'translate(-50%, -50%)';
      }
      if (locationDisplay) locationDisplay.style.display = 'block';
      if (alertType) alertType.style.display = 'none';
      const alertTypeLabel = document.querySelector('#detailedAlertBox label[for="alertType"]');
      if (alertTypeLabel) alertTypeLabel.style.display = 'none';
      if (clickLocationBtn) clickLocationBtn.style.display = 'none';
      if (alertCurrentBtn) alertCurrentBtn.style.display = 'none';
      if (postAlertBtn) postAlertBtn.style.display = 'block';
      if (cancelAlertBtn) cancelAlertBtn.style.display = 'block';
      showToastMessage('Current location selected for alert.', 5000);
    }, (error) => {
      console.error('Geolocation error:', error);
      showToastMessage('Failed to get current location.', 7000, true);
    });
  }

  function fetchAlerts() {
    fetchWithTokenRefresh(`${BASE_URL}/api/alerts`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    })
      .then(response => response.json())
      .then(data => {
        alerts = data;
        if (currentTab === 'alerts') {
          updateAlertTable();
        }
      })
      .catch(err => console.error('Fetch alerts error:', err.message));
  }

  function updateAlertTable() {
    const typeFilter = document.getElementById('alert-type-filter').value;
    const userFilter = document.getElementById('alert-user-filter').value;
    const filteredAlerts = alerts.filter(alert => {
      return (!typeFilter || alert.type === typeFilter) &&
             (!userFilter || alert.username === userFilter);
    });

    const totalPages = Math.ceil(filteredAlerts.length / alertsPerPage);
    currentPage = Math.min(currentPage, totalPages || 1);
    const startIndex = (currentPage - 1) * alertsPerPage;
    const endIndex = startIndex + alertsPerPage;
    const paginatedAlerts = filteredAlerts.slice(startIndex, endIndex);

    alertTable.innerHTML = `
      <tr>
        <th>Type</th>
        <th>Notes</th>
        <th>Timestamp</th>
        <th>User</th>
        <th>Action</th>
      </tr>
    `;

    paginatedAlerts.forEach(alert => {
      const row = document.createElement('tr');
      row.innerHTML = `
        <td>${alert.type}</td>
        <td>${alert.notes || 'None'}</td>
        <td>${new Date(alert.createdAt).toLocaleString()}</td>
        <td>${alert.username}</td>
        <td class="action-cell">
          <button class="delete-btn" data-id="${alert._id}"><i class="fas fa-times"></i></button>
          <button class="info-btn" data-id="${alert._id}"><i class="fas fa-info-circle"></i></button>
        </td>
      `;
      const detailsRow = document.createElement('tr');
      detailsRow.className = 'details-row';
      detailsRow.dataset.id = alert._id;
      detailsRow.innerHTML = `
        <td colspan="5" class="details-content">
          <p><span>User:</span> ${alert.username}</p>
          <p><span>Timestamp:</span> ${new Date(alert.createdAt).toLocaleString()}</p>
          <p><span>Location:</span> ${alert.location.coordinates[1].toFixed(6)}, ${alert.location.coordinates[0].toFixed(6)}</p>
          <p><span>Notes:</span> ${alert.notes || 'None'}</p>
          <button class="collapse-btn"><i class="fas fa-caret-up"></i></button>
        </td>
      `;
      alertTable.appendChild(row);
      alertTable.appendChild(detailsRow);

      const deleteBtn = row.querySelector('.delete-btn');
      const infoBtn = row.querySelector('.info-btn');
      const collapseBtn = detailsRow.querySelector('.collapse-btn');

      deleteBtn.addEventListener('click', () => {
        fetchWithTokenRefresh(`${BASE_URL}/api/alerts/${alert._id}`, {
          method: 'DELETE',
          headers: { 'Content-Type': 'application/json' },
        })
          .then(response => {
            if (!response.ok) throw new Error('Failed to delete alert');
            socket.emit('removeAlert', alert._id);
            alerts = alerts.filter(a => a._id !== alert._id);
            updateAlertTable();
            showToastMessage('Alert deleted successfully.', 5000);
          })
          .catch(err => {
            console.error('Delete alert error:', err.message);
            showToastMessage('Failed to delete alert.', 7000, true);
          });
      });
      deleteBtn.addEventListener('touchend', (e) => {
        e.preventDefault();
        deleteBtn.click();
      }, { passive: false });

      infoBtn.addEventListener('click', () => {
        const isActive = detailsRow.classList.contains('active');
        document.querySelectorAll('.details-row').forEach(row => row.classList.remove('active'));
        if (!isActive) {
          detailsRow.classList.add('active');
        }
      });
      infoBtn.addEventListener('touchend', (e) => {
        e.preventDefault();
        infoBtn.click();
      }, { passive: false });

      collapseBtn.addEventListener('click', () => {
        detailsRow.classList.remove('active');
      });
      collapseBtn.addEventListener('touchend', (e) => {
        e.preventDefault();
        collapseBtn.click();
      }, { passive: false });
    });

    alertPagination.innerHTML = '';
    if (totalPages > 1) {
      const prevBtn = document.createElement('button');
      prevBtn.textContent = '<';
      prevBtn.disabled = currentPage === 1;
      prevBtn.addEventListener('click', () => {
        if (currentPage > 1) {
          currentPage--;
          updateAlertTable();
        }
      });
      prevBtn.addEventListener('touchend', (e) => {
        e.preventDefault();
        prevBtn.click();
      }, { passive: false });
      alertPagination.appendChild(prevBtn);

      for (let i = 1; i <= totalPages; i++) {
        const pageBtn = document.createElement('button');
        pageBtn.textContent = i;
        pageBtn.classList.toggle('active', i === currentPage);
        pageBtn.addEventListener('click', () => {
          currentPage = i;
          updateAlertTable();
        });
        pageBtn.addEventListener('touchend', (e) => {
          e.preventDefault();
          pageBtn.click();
        }, { passive: false });
        alertPagination.appendChild(pageBtn);
      }

      const nextBtn = document.createElement('button');
      nextBtn.textContent = '>';
      nextBtn.disabled = currentPage === totalPages;
      nextBtn.addEventListener('click', () => {
        if (currentPage < totalPages) {
          currentPage++;
          updateAlertTable();
        }
      });
      nextBtn.addEventListener('touchend', (e) => {
        e.preventDefault();
        nextBtn.click();
      }, { passive: false });
      alertPagination.appendChild(nextBtn);
    }
  }

  function showToastMessage(message, duration, isError = false) {
    const toast = document.getElementById('toast-message');
    toast.textContent = message;
    toast.classList.toggle('error', isError);
    toast.style.display = 'block';
    toast.style.opacity = '1';
    setTimeout(() => {
      toast.style.opacity = '0';
      setTimeout(() => {
        toast.style.display = 'none';
      }, 200);
    }, duration);
  }

  function enableMapClick() {
    if (isSelectingLocation) return;
    isSelectingLocation = true;
    const detailedAlertBox = document.getElementById('detailedAlertBox');
    if (detailedAlertBox) {
      detailedAlertBox.classList.remove('active');
      detailedAlertBox.style.display = 'none';
    }
    showToastMessage('Waiting for click or press a location on the map.', 5000);
    const clickListener = map.addListener('click', (event) => {
      const lat = event.latLng.lat();
      const lng = event.latLng.lng();
      reverseGeocode(lat, lng).then(address => {
        if (selectedLocation) selectedLocation.textContent = `${lat.toFixed(6)}, ${lng.toFixed(6)}`;
        if (detailedAlertBox) {
          detailedAlertBox.classList.add('active');
          detailedAlertBox.style.display = 'flex';
          detailedAlertBox.style.left = '50%';
          detailedAlertBox.style.top = '50%';
          detailedAlertBox.style.transform = 'translate(-50%, -50%)';
        }
        if (locationDisplay) locationDisplay.style.display = 'block';
        if (alertType) alertType.style.display = 'none';
        const alertTypeLabel = document.querySelector('#detailedAlertBox label[for="alertType"]');
        if (alertTypeLabel) alertTypeLabel.style.display = 'none';
        if (clickLocationBtn) clickLocationBtn.style.display = 'none';
        if (alertCurrentBtn) alertCurrentBtn.style.display = 'none';
        if (postAlertBtn) postAlertBtn.style.display = 'block';
        if (cancelAlertBtn) cancelAlertBtn.style.display = 'block';
        isSelectingLocation = false;
        google.maps.event.removeListener(clickListener);
      }).catch(err => {
        console.error('Reverse geocode error:', err);
        if (selectedLocation) selectedLocation.textContent = `${lat.toFixed(6)}, ${lng.toFixed(6)}`;
        if (detailedAlertBox) {
          detailedAlertBox.classList.add('active');
          detailedAlertBox.style.display = 'flex';
          detailedAlertBox.style.left = '50%';
          detailedAlertBox.style.top = '50%';
          detailedAlertBox.style.transform = 'translate(-50%, -50%)';
        }
        if (locationDisplay) locationDisplay.style.display = 'block';
        if (alertType) alertType.style.display = 'none';
        const alertTypeLabel = document.querySelector('#detailedAlertBox label[for="alertType"]');
        if (alertTypeLabel) alertTypeLabel.style.display = 'none';
        if (clickLocationBtn) clickLocationBtn.style.display = 'none';
        if (alertCurrentBtn) alertCurrentBtn.style.display = 'none';
        if (postAlertBtn) postAlertBtn.style.display = 'block';
        if (cancelAlertBtn) cancelAlertBtn.style.display = 'block';
        isSelectingLocation = false;
        google.maps.event.removeListener(clickListener);
      });
    });
    const touchListener = map.addListener('click', (event) => {
      if (event.domEvent.type === 'touchend') {
        const lat = event.latLng.lat();
        const lng = event.latLng.lng();
        reverseGeocode(lat, lng).then(address => {
          if (selectedLocation) selectedLocation.textContent = `${lat.toFixed(6)}, ${lng.toFixed(6)}`;
          if (detailedAlertBox) {
            detailedAlertBox.classList.add('active');
            detailedAlertBox.style.display = 'flex';
            detailedAlertBox.style.left = '50%';
            detailedAlertBox.style.top = '50%';
            detailedAlertBox.style.transform = 'translate(-50%, -50%)';
          }
          if (locationDisplay) locationDisplay.style.display = 'block';
          if (alertType) alertType.style.display = 'none';
          const alertTypeLabel = document.querySelector('#detailedAlertBox label[for="alertType"]');
          if (alertTypeLabel) alertTypeLabel.style.display = 'none';
          if (clickLocationBtn) clickLocationBtn.style.display = 'none';
          if (alertCurrentBtn) alertCurrentBtn.style.display = 'none';
          if (postAlertBtn) postAlertBtn.style.display = 'block';
          if (cancelAlertBtn) cancelAlertBtn.style.display = 'block';
          isSelectingLocation = false;
          google.maps.event.removeListener(touchListener);
        }).catch(err => {
          console.error('Reverse geocode error:', err);
          if (selectedLocation) selectedLocation.textContent = `${lat.toFixed(6)}, ${lng.toFixed(6)}`;
          if (detailedAlertBox) {
            detailedAlertBox.classList.add('active');
            detailedAlertBox.style.display = 'flex';
            detailedAlertBox.style.left = '50%';
            detailedAlertBox.style.top = '50%';
            detailedAlertBox.style.transform = 'translate(-50%, -50%)';
          }
          if (locationDisplay) locationDisplay.style.display = 'block';
          if (alertType) alertType.style.display = 'none';
          const alertTypeLabel = document.querySelector('#detailedAlertBox label[for="alertType"]');
          if (alertTypeLabel) alertTypeLabel.style.display = 'none';
          if (clickLocationBtn) clickLocationBtn.style.display = 'none';
          if (alertCurrentBtn) alertCurrentBtn.style.display = 'none';
          if (postAlertBtn) postAlertBtn.style.display = 'block';
          if (cancelAlertBtn) cancelAlertBtn.style.display = 'block';
          isSelectingLocation = false;
          google.maps.event.removeListener(touchListener);
        });
      }
    });
  }

  function postSelectedAlert() {
    const alertType = document.getElementById('alertType');
    const alertNotes = document.getElementById('alertNotes');
    const selectedLocation = document.getElementById('selected-location');
    if (!alertType || !alertNotes || !selectedLocation) {
      console.error('Missing elements for posting alert:', { alertType: !!alertType, alertNotes: !!alertNotes, selectedLocation: !!selectedLocation });
      showToastMessage('Error: Required elements not found.', 7000, true);
      return;
    }
    const type = alertType.value;
    const notes = alertNotes.value.trim();
    const [lat, lng] = selectedLocation.textContent.split(', ').map(Number);
    const detailedAlertBox = document.getElementById('detailedAlertBox');
    if (detailedAlertBox) {
      detailedAlertBox.style.opacity = '0';
      setTimeout(() => {
        detailedAlertBox.classList.remove('active');
        detailedAlertBox.style.display = 'none';
        detailedAlertBox.style.left = '50%';
        detailedAlertBox.style.top = '50%';
        detailedAlertBox.style.transform = 'translate(-50%, -50%)';
        addAlert(type, notes, new google.maps.LatLng(lat, lng)).then(() => {
          showToastMessage('Your alert has been posted. Thank you!', 5000);
        }).catch(err => {
          showToastMessage(err.message || 'Failed to post alert.', 7000, true);
        });
      }, 200);
    }
  }

  function reverseGeocode(lat, lng) {
    return new Promise((resolve, reject) => {
      if (!window.google || !google.maps) {
        reject(new Error('Google Maps API not loaded'));
        return;
      }
      const geocoder = new google.maps.Geocoder();
      geocoder.geocode({ location: { lat, lng } }, (results, status) => {
        if (status === google.maps.GeocoderStatus.OK && results[0]) {
          resolve(results[0].formatted_address);
        } else {
          reject(new Error('Reverse geocoding failed'));
        }
      });
    });
  }

  function makeDraggable(element) {
    let isDragging = false;
    let currentX = window.innerWidth / 2;
    let currentY = window.innerHeight / 2;
    let initialX = 0;
    let initialY = 0;
    let xOffset = 0;
    let yOffset = 0;
    element.style.position = 'fixed';
    element.style.left = '50%';
    element.style.top = '50%';
    element.style.transform = 'translate(-50%, -50%)';
    const h3 = element.querySelector('h3');
    if (h3) {
      const startDrag = (clientX, clientY, e) => {
        if (e.target !== h3) return;
        initialX = clientX - xOffset;
        initialY = clientY - yOffset;
        isDragging = true;
        element.classList.add('dragging');
        console.log('Started dragging detailedAlertBox');
        e.preventDefault();
      };
      h3.addEventListener('mousedown', (e) => startDrag(e.clientX, e.clientY, e));
      h3.addEventListener('touchstart', (e) => {
        const touch = e.touches[0];
        startDrag(touch.clientX, touch.clientY, e);
      }, { passive: false });
    }
    function updatePosition(clientX, clientY) {
      if (isDragging) {
        currentX = clientX - initialX;
        currentY = clientY - initialY;
        xOffset = currentX;
        yOffset = currentY;
        const rect = element.getBoundingClientRect();
        const maxX = window.innerWidth - rect.width - 15;
        const maxY = window.innerHeight - rect.height - 15;
        currentX = Math.max(15, Math.min(currentX, maxX));
        currentY = Math.max(15, Math.min(currentY, maxY));
        element.style.left = currentX + 'px';
        element.style.top = currentY + 'px';
        element.style.transform = 'none';
        if (isDragging) requestAnimationFrame(() => updatePosition(clientX, clientY));
      }
    }
    document.addEventListener('mousemove', (e) => {
      if (isDragging) {
        e.preventDefault();
        updatePosition(e.clientX, e.clientY);
      }
    }, { passive: false });
    document.addEventListener('touchmove', (e) => {
      if (isDragging) {
        e.preventDefault();
        const touch = e.touches[0];
        updatePosition(touch.clientX, touch.clientY);
      }
    }, { passive: false });
    const stopDrag = (e) => {
      isDragging = false;
      element.classList.remove('dragging');
      console.log('Stopped dragging detailedAlertBox at:', { left: element.style.left, top: element.style.top });
      e.preventDefault();
    };
    document.addEventListener('mouseup', stopDrag);
    document.addEventListener('touchend', stopDrag, { passive: false });
  }

  if (navAddress) {
    navAddress.addEventListener('input', () => {
      const query = navAddress.value.trim();
      if (query.length > 2) {
        autocompleteService.getPlacePredictions({ input: query }, (predictions, status) => {
          if (status === google.maps.places.PlacesServiceStatus.OK && predictions) {
            suggestions.innerHTML = '';
            predictions.forEach(prediction => {
              const item = document.createElement('div');
              item.className = 'suggestion-item';
              item.textContent = prediction.description;
              const handleSelect = () => {
                navAddress.value = prediction.description;
                startNavigation(prediction.description);
                navOverlay.style.display = 'none';
              };
              item.addEventListener('click', handleSelect);
              item.addEventListener('touchend', handleSelect, { passive: false });
              suggestions.appendChild(item);
            });
            showOverlay();
          }
        });
      }
    });
  }

  if (closeOverlay) {
    const handleCloseOverlay = () => {
      navOverlay.style.display = 'none';
      showToastMessage('Navigation overlay closed.', 5000);
    };
    closeOverlay.addEventListener('click', handleCloseOverlay);
    closeOverlay.addEventListener('touchend', handleCloseOverlay, { passive: false });
  }

  if (cancelBtn) {
    const handleCancel = () => stopNavigation();
    cancelBtn.addEventListener('click', handleCancel);
    cancelBtn.addEventListener('touchend', handleCancel, { passive: false });
  }

  if (recenterBtn) {
    const handleRecenter = () => recenterMap();
    recenterBtn.addEventListener('click', handleRecenter);
    recenterBtn.addEventListener('touchend', handleRecenter, { passive: false });
  }

  if (muteBtn) {
    const handleMute = () => {
      isMuted = !isMuted;
      muteBtn.classList.toggle('muted', isMuted);
      showToastMessage(isMuted ? 'Voice navigation muted.' : 'Voice navigation unmuted.', 5000);
    };
    muteBtn.addEventListener('click', handleMute);
    muteBtn.addEventListener('touchend', handleMute, { passive: false });
  }

  if (hazardBtn) {
    const handleHazard = () => addHazardMarker();
    hazardBtn.addEventListener('click', handleHazard);
    hazardBtn.addEventListener('touchend', handleHazard, { passive: false });
  }

  if (micButton) {
    const handleMic = () => startVoiceRecognition();
    micButton.addEventListener('click', handleMic);
    micButton.addEventListener('touchend', handleMic, { passive: false });
  }

  if (closeVoiceOverlay) {
    const handleCloseVoice = () => {
      stopVoiceRecognition();
      voiceOverlay.style.display = 'none';
      showToastMessage('Voice overlay closed.', 5000);
    };
    closeVoiceOverlay.addEventListener('click', handleCloseVoice);
    closeVoiceOverlay.addEventListener('touchend', handleCloseVoice, { passive: false });
  }

  if (detailedAlertBtn) {
    const handleDetailedAlert = () => showDetailedAlertBox();
    detailedAlertBtn.addEventListener('click', handleDetailedAlert);
    detailedAlertBtn.addEventListener('touchend', handleDetailedAlert, { passive: false });
  }

  if (closeDetailedAlertBtn) {
    const handleCloseDetailed = () => {
      detailedAlertBox.classList.remove('active');
      detailedAlertBox.style.display = 'none';
      showToastMessage('Detailed alert box closed.', 5000);
    };
    closeDetailedAlertBtn.addEventListener('click', handleCloseDetailed);
    closeDetailedAlertBtn.addEventListener('touchend', handleCloseDetailed, { passive: false });
  }

  if (clickLocationBtn) {
    const handleClickLocation = () => enableMapClick();
    clickLocationBtn.addEventListener('click', handleClickLocation);
    clickLocationBtn.addEventListener('touchend', handleClickLocation, { passive: false });
  }

  if (alertCurrentBtn) {
    const handleAlertCurrent = () => alertAtCurrentLocation();
    alertCurrentBtn.addEventListener('click', handleAlertCurrent);
    alertCurrentBtn.addEventListener('touchend', handleAlertCurrent, { passive: false });
  }

  if (postAlertBtn) {
    const handlePostAlert = () => postSelectedAlert();
    postAlertBtn.addEventListener('click', handlePostAlert);
    postAlertBtn.addEventListener('touchend', handlePostAlert, { passive: false });
  }

  if (cancelAlertBtn) {
    const handleCancelAlert = () => {
      detailedAlertBox.classList.remove('active');
      detailedAlertBox.style.display = 'none';
      showToastMessage('Alert creation cancelled.', 5000);
    };
    cancelAlertBtn.addEventListener('click', handleCancelAlert);
    cancelAlertBtn.addEventListener('touchend', handleCancelAlert, { passive: false });
  }

  if (profileBtn) {
    const handleProfile = () => {
      profileHud.style.display = 'flex';
      profileHud.classList.add('active');
    };
    profileBtn.addEventListener('click', handleProfile);
    profileBtn.addEventListener('touchend', handleProfile, { passive: false });
  }

  if (closeBtn) {
    const handleCloseProfile = () => {
      profileHud.classList.remove('active');
      profileHud.style.display = 'none';
    };
    closeBtn.addEventListener('click', handleCloseProfile);
    closeBtn.addEventListener('touchend', handleCloseProfile, { passive: false });
  }

  if (tabButtons) {
    tabButtons.forEach(button => {
      const handleTabClick = () => {
        tabButtons.forEach(btn => btn.classList.remove('active'));
        button.classList.add('active');
        currentTab = button.dataset.tab;
        accountInfo.classList.remove('active');
        editProfile.classList.remove('active');
        alertsTab.classList.remove('active');
        if (currentTab === 'account') accountInfo.classList.add('active');
        else if (currentTab === 'edit') editProfile.classList.add('active');
        else if (currentTab === 'alerts') {
          alertsTab.classList.add('active');
          updateAlertTable();
        }
      };
      button.addEventListener('click', handleTabClick);
      button.addEventListener('touchend', handleTabClick, { passive: false });
    });
  }

  if (saveProfileBtn) {
    const handleSaveProfile = () => {
      const updates = {
        name: document.getElementById('edit-name')?.value.trim() || '',
        username: document.getElementById('edit-username')?.value.trim() || '',
        email: document.getElementById('edit-email')?.value.trim() || '',
        age: document.getElementById('edit-age')?.value.trim() || '',
        dob: document.getElementById('edit-dob')?.value.trim() || '',
        location: document.getElementById('edit-location')?.value.trim() || ''
      };
      const token = localStorage.getItem('token');
      if (!token) {
        console.error('No token available for profile update');
        return;
      }
      fetchWithTokenRefresh(`${BASE_URL}/api/auth/update`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify(updates)
      })
        .then(response => {
          if (!response.ok) throw new Error(`Profile update failed: ${response.status}`);
          return response.json();
        })
        .then(data => {
          userProfile = data;
          currentUser = { ...currentUser, username: data.username, id: data._id };
          updateProfileDisplay();
          updateEditProfileForm();
          showToastMessage('Profile updated successfully.', 5000);
        })
        .catch(err => {
          console.error('Profile update error:', err.message);
          showToastMessage('Failed to update profile.', 7000, true);
        });
    };
    saveProfileBtn.addEventListener('click', handleSaveProfile);
    saveProfileBtn.addEventListener('touchend', (e) => {
      e.preventDefault();
      handleSaveProfile();
    }, { passive: false });
  }

  if (settingsBtn) {
    const handleSettings = () => {
      settingsHud.style.display = 'flex';
      settingsHud.classList.add('active');
    };
    settingsBtn.addEventListener('click', handleSettings);
    settingsBtn.addEventListener('touchend', handleSettings, { passive: false });
  }

  if (closeSettings) {
    const handleCloseSettings = () => {
      settingsHud.classList.remove('active');
      settingsHud.style.display = 'none';
      showToastMessage('Settings closed.', 5000);
    };
    closeSettings.addEventListener('click', handleCloseSettings);
    closeSettings.addEventListener('touchend', handleCloseSettings, { passive: false });
  }

  if (rerouteYes) {
    const handleRerouteYes = () => {
      showToastMessage('Rerouting...', 5000);
      // Implement rerouting logic here
    };
    rerouteYes.addEventListener('click', handleRerouteYes);
    rerouteYes.addEventListener('touchend', handleRerouteYes, { passive: false });
  }

  if (rerouteNo) {
    const handleRerouteNo = () => {
      showToastMessage('Reroute ignored.', 5000);
      document.getElementById('reroutePrompt').style.display = 'none';
    };
    rerouteNo.addEventListener('click', handleRerouteNo);
    rerouteNo.addEventListener('touchend', handleRerouteNo, { passive: false });
  }

  if (addAlertBtn) {
    const handleAddAlert = () => {
      showDetailedAlertBox();
    };
    addAlertBtn.addEventListener('click', handleAddAlert);
    addAlertBtn.addEventListener('touchend', handleAddAlert, { passive: false });
  }

  if (detailedAlertBox) {
    makeDraggable(detailedAlertBox);
  }

  if (loginBtn && loginUsername && loginPassword) {
    const handleLogin = () => {
      const username = loginUsername.value.trim();
      const password = loginPassword.value.trim();
      if (!username || !password) {
        showToastMessage('Please enter username and password.', 7000, true);
        loginUsername.classList.add('invalid');
        loginPassword.classList.add('invalid');
        return;
      }
      login(username, password, loginBtn, loginUsername, loginPassword);
    };
    loginBtn.addEventListener('click', handleLogin);
    loginBtn.addEventListener('touchend', (e) => {
      e.preventDefault();
      handleLogin();
    }, { passive: false });
  }

  console.timeEnd('DOM initialization');
});