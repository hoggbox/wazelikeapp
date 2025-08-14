const VERSION = '1.0.43'; // Updated version for cache busting
// Global variables
let map;
let routePolyline;
let currentDestination = null;
let liveLocationMarker = null;
let isNavigating = false;
let previousPosition = null;
let routePath = [];
let recentDestinations = ['1827 Holly Hill Rd, Milledgeville, GA 31061', 'Walmart Milledgeville GA'];
let autocompleteService;
let placesService;
let directionsService; // For Google Directions API
let directionsRenderer; // For rendering routes
let userLocation = { lat: 33.0891264, lng: -83.2372736 }; // Default position
let socket = null;
let recognition = null;
let isMuted = false;
let hazardMarkers = [];
let lastLocationUpdate = 0;
let isSelectingLocation = false;
let alertMarkers = new Map();
let alertQueue = [];
let lastHazardTime = 0;
let currentUser = null;
let userProfile = { name: '', username: '', email: '', age: '', dob: null, location: '', _id: null, lastUsernameChange: null };
let allAlerts = [];
let ignoredHazards = [];
let currentHazards = [];
const GOOGLE_MAPS_API_KEY = 'AIzaSyBSW8iQAE1AjjouEu4df-Cvq1ceUMLBit4';
const ALERTS_PER_PAGE = 4;
let currentPage = 1;
let currentTab = 'account';
let accountInfo, editProfile, alertsTab, tabButtons;
let femaleVoice = null;
let mapReadyResolve;
const mapReady = new Promise((resolve) => mapReadyResolve = resolve);

// Determine API and Socket.IO base URL based on environment
const isLocal = window.location.hostname === '127.0.0.1' || window.location.hostname === 'localhost';
const BASE_URL = isLocal ? 'http://127.0.0.1:3000' : 'https://wazelikeapp.onrender.com';
console.log(`Environment: ${isLocal ? 'Local' : 'Render'}, Base URL: ${BASE_URL}`);

console.log(`Loading map.js version ${VERSION}`);

// Load voices for speech synthesis
if ('speechSynthesis' in window) {
  function loadVoices() {
    let voices = window.speechSynthesis.getVoices();
    femaleVoice = voices.find(voice => voice.name.includes('Female') || (voice.lang.startsWith('en-') && !voice.name.includes('Male'))) || voices.find(voice => voice.lang.startsWith('en-')) || voices[0];
    console.log('Loaded voice:', femaleVoice ? femaleVoice.name : 'None available');
  }
  loadVoices();
  window.speechSynthesis.onvoiceschanged = loadVoices;
}

// Utility functions
function showToastMessage(message, duration = 5000) {
  const toastMessage = document.getElementById('toast-message');
  if (toastMessage) {
    toastMessage.textContent = message;
    toastMessage.style.display = 'block';
    setTimeout(() => {
      toastMessage.style.display = 'none';
    }, duration);
  } else {
    console.warn('toastMessage element not found, message:', message);
  }
}

function geocodeWithGoogle(address) {
  return fetch(`https://maps.googleapis.com/maps/api/geocode/json?address=${encodeURIComponent(address)}&key=${GOOGLE_MAPS_API_KEY}`)
    .then(response => {
      if (!response.ok) throw new Error(`Google API error! status: ${response.status}`);
      return response.json();
    })
    .then(data => {
      if (data.results && data.results.length > 0) {
        const { lat, lng } = data.results[0].geometry.location;
        console.log(`Geocoded with Google API to [${lat}, ${lng}]`);
        return [lat, lng];
      }
      console.log('No Google API results for:', address);
      return null;
    })
    .catch(err => {
      console.error('Google API geocode error:', err);
      return null;
    });
}

function provideVoiceNavigation(coords) {
  if (routePath.length > 1 && coords.heading !== undefined) {
    const currentPos = new google.maps.LatLng(coords.latitude, coords.longitude);
    const closest = findClosestPointOnRoute(currentPos, routePath);
    const nextIndex = Math.min(closest.index + 1, routePath.length - 1);
    const distance = closest.distance;
    const nextPoint = routePath[nextIndex];
    console.log('Navigation check:', { distance, nextIndex, heading: coords.heading });
    if (distance < 50 && nextIndex < routePath.length - 1) {
      const nextNextPoint = routePath[nextIndex + 1];
      const heading = google.maps.geometry.spherical.computeHeading(currentPos, nextNextPoint);
      const currentHeading = coords.heading;
      let instruction = '';
      const angleDiff = Math.abs(heading - currentHeading) % 360;
      const turnAngle = Math.min(angleDiff, 360 - angleDiff);
      if (turnAngle > 45) {
        instruction = `Turn ${heading > currentHeading ? 'right' : 'left'} in 50 meters.`;
      } else {
        instruction = 'Continue straight for 50 meters.';
      }
      if (!isMuted && 'speechSynthesis' in window && femaleVoice) {
        const utterance = new SpeechSynthesisUtterance(instruction);
        utterance.voice = femaleVoice;
        utterance.lang = 'en-US';
        utterance.volume = 1.0;
        utterance.rate = 1.1;
        window.speechSynthesis.speak(utterance);
        console.log('Voice navigation:', instruction, 'with:', femaleVoice.name);
      } else if (!femaleVoice) {
        console.warn('No female voice available, skipping navigation instruction');
      }
    }
  } else if (isNavigating && routePath.length > 0) {
    console.warn('Missing heading or route data for voice navigation:', { heading: coords.heading, routePathLength: routePath.length });
  }
  checkHazardsOnRoute();
}

function findClosestPointOnRoute(currentPos, routePath) {
  let closestDistance = Infinity;
  let closestIndex = 0;
  routePath.forEach((point, index) => {
    const distance = google.maps.geometry.spherical.computeDistanceBetween(currentPos, point);
    if (distance < closestDistance) {
      closestDistance = distance;
      closestIndex = index;
    }
  });
  return { index: closestIndex, distance: closestDistance };
}

function checkHazardsOnRoute() {
  if (!isNavigating || routePath.length === 0) return;
  currentHazards = [];
  const userPos = new google.maps.LatLng(userLocation.lat, userLocation.lng);
  allAlerts.forEach(alert => {
    if (alert.type === 'Hazard' && !ignoredHazards.includes(alert._id)) {
      const alertPos = new google.maps.LatLng(alert.location.coordinates[1], alert.location.coordinates[0]);
      const distanceToRoute = routePath.reduce((minDist, point) => {
        return Math.min(minDist, google.maps.geometry.spherical.computeDistanceBetween(alertPos, point));
      }, Infinity);
      const distanceToUser = google.maps.geometry.spherical.computeDistanceBetween(userPos, alertPos) / 1609.34;
      if (distanceToRoute < 500 && distanceToUser < 5) {
        currentHazards.push(alert);
      }
    }
  });
  if (currentHazards.length > 0) {
    const reroutePrompt = document.getElementById('reroutePrompt');
    if (reroutePrompt && reroutePrompt.style.display !== 'flex') {
      reroutePrompt.style.display = 'flex';
      console.log('Hazard detected on route, showing reroute prompt:', currentHazards);
    }
  } else {
    const reroutePrompt = document.getElementById('reroutePrompt');
    if (reroutePrompt) reroutePrompt.style.display = 'none';
  }
}

function rerouteAroundHazards(hazards) {
  if (!currentDestination || !isNavigating) {
    console.warn('No destination or navigation active, cannot reroute');
    return;
  }
  console.log('Rerouting around hazards:', hazards);
  updateRoute([userLocation.lat, userLocation.lng], currentDestination, true);
  const reroutePrompt = document.getElementById('reroutePrompt');
  if (reroutePrompt) {
    reroutePrompt.style.display = 'none';
    console.log('Reroute prompt hidden after rerouting');
  }
  ignoredHazards.push(...hazards.map(h => h._id)); // Ignore these hazards to prevent re-prompting
}

function ignoreHazards(hazards) {
  hazards.forEach(h => ignoredHazards.push(h._id));
  const reroutePrompt = document.getElementById('reroutePrompt');
  if (reroutePrompt) {
    reroutePrompt.style.display = 'none';
    console.log('Ignoring hazards:', hazards);
  }
}

async function updateRoute(start, end, avoidHazards = false) {
  await mapReady;
  try {
    console.time('Route calculation');
    console.log(`Fetching route from [${start}] to [${end}] with avoidHazards: ${avoidHazards}`);
    const request = {
      origin: new google.maps.LatLng(start[0], start[1]),
      destination: new google.maps.LatLng(end[0], end[1]),
      travelMode: google.maps.TravelMode.DRIVING,
      provideRouteAlternatives: avoidHazards, // Request alternative routes if avoiding hazards
      avoidTolls: true,
      avoidHighways: false,
      avoidFerries: true
    };
    const response = await new Promise((resolve, reject) => {
      directionsService.route(request, (result, status) => {
        if (status === google.maps.DirectionsStatus.OK) {
          resolve(result);
        } else {
          reject(new Error(`Directions request failed: ${status}`));
        }
      });
    });
    console.log('Google Directions response:', response);
    let selectedRouteIndex = 0;
    if (avoidHazards && response.routes.length > 1) {
      let maxMinDistance = 0;
      response.routes.forEach((route, index) => {
        const path = route.legs.reduce((acc, leg) => acc.concat(leg.steps.reduce((stepAcc, step) => stepAcc.concat(google.maps.geometry.encoding.decodePath(step.polyline.points)), [])), []);
        let minDistanceToHazards = Infinity;
        currentHazards.forEach(hazard => {
          const hazardPos = new google.maps.LatLng(hazard.location.coordinates[1], hazard.location.coordinates[0]);
          path.forEach(point => {
            const dist = google.maps.geometry.spherical.computeDistanceBetween(point, hazardPos);
            if (dist < minDistanceToHazards) minDistanceToHazards = dist;
          });
        });
        if (minDistanceToHazards > maxMinDistance) {
          maxMinDistance = minDistanceToHazards;
          selectedRouteIndex = index;
        }
      });
      console.log(`Selected alternative route index: ${selectedRouteIndex} with min hazard distance: ${maxMinDistance}m`);
    }
    const selectedRoute = response.routes[selectedRouteIndex];
    directionsRenderer.setDirections(response);
    directionsRenderer.setRouteIndex(selectedRouteIndex);
    const path = selectedRoute.legs.reduce((acc, leg) => acc.concat(leg.steps.reduce((stepAcc, step) => stepAcc.concat(google.maps.geometry.encoding.decodePath(step.polyline.points)), [])), []);
    routePath = path;
    if (routePolyline) routePolyline.setMap(null);
    routePolyline = new google.maps.Polyline({
      path: path,
      strokeColor: '#ff4444',
      strokeOpacity: 1.0,
      strokeWeight: 4,
      map: map
    });
    const timeMs = selectedRoute.legs.reduce((acc, leg) => acc + leg.duration.value * 1000, 0);
    const distanceM = selectedRoute.legs.reduce((acc, leg) => acc + leg.distance.value, 0);
    if (eta) eta.textContent = `${Math.round(timeMs / 60000)} min`;
    if (dta) dta.textContent = `${Math.round(distanceM / 1609.34)} mi`;
    console.timeEnd('Route calculation');
  } catch (err) {
    console.error('Route calculation failed:', err);
    showToastMessage('Failed to calculate route. Please try again.', 7000);
  }
}

function addMarker(type, notes = '', position) {
  const timerName = `Add ${type} marker ${Date.now()}`;
  console.time(timerName);
  console.log(`Adding ${type} marker at:`, position.toString(), 'with currentUser:', currentUser);
  const marker = new google.maps.Marker({
    position: position,
    map: map,
    icon: {
      path: google.maps.SymbolPath.CIRCLE,
      fillColor: type === 'Hazard' ? '#e74c3c' : '#f1c40f',
      fillOpacity: 1,
      strokeWeight: 2,
      strokeColor: '#ffffff',
      scale: 10
    },
    title: `${type} Alert: ${notes || 'No notes'}`
  });
  const timestamp = Date.now();
  const alertData = { 
    latitude: position.lat(), 
    longitude: position.lng(), 
    type, 
    notes, 
    timestamp, 
    user: { username: currentUser?.username || userProfile?.username || 'Anonymous', id: currentUser?.id || userProfile?._id }
  };
  let attempts = 0;
  const maxAttempts = 3;
  function trySave() {
    const token = localStorage.getItem('token');
    if (!token || !currentUser) {
      console.error('No token or user available, queuing marker offline:', position.toString());
      marker.setMap(map);
      alertQueue.push(alertData);
      hazardMarkers.push({ marker, timestamp, type, _id: null });
      alertMarkers.set(null, marker);
      console.timeEnd(timerName);
      showToastMessage('No user logged in, alert queued offline.', 7000);
      return;
    }
    fetch(`${BASE_URL}/api/map/alert`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify(alertData)
    })
      .then(response => {
        console.log('Alert POST response status:', response.status);
        if (!response.ok) return response.json().then(data => { throw new Error(data.msg || `HTTP error! status: ${response.status}`) });
        return response.json();
      })
      .then(data => {
        if (data.msg === 'Duplicate alert detected') {
          console.log('Duplicate alert not saved:', data.alert._id);
          marker.setMap(null);
          return;
        }
        alertData._id = data._id;
        hazardMarkers.push({ marker, timestamp, type, _id: data._id });
        alertMarkers.set(data._id, marker);
        console.log(`${type} marker added with ID: ${data._id} at:`, position.toString(), 'at', new Date(timestamp).toLocaleString());
        socket?.emit(type === 'Hazard' ? 'hazard' : 'detailedAlert', { ...alertData, _id: data._id });
        if (alertQueue.length > 0) {
          alertQueue.forEach(queued => addMarker(queued.type, queued.notes, new google.maps.LatLng(queued.latitude, queued.longitude)));
          alertQueue = [];
        }
        if (currentUser) {
          fetchAlerts();
          setTimeout(checkHazardsOnRoute, 1000);
        }
        console.timeEnd(timerName);
      })
      .catch(err => {
        console.error('Failed to save alert (attempt ' + attempts + '):', err.message);
        if (err.message.includes('User not found') || err.message.includes('Invalid token')) {
          console.warn('Authentication error detected, logging out');
          logout();
          return;
        }
        if (attempts < maxAttempts) {
          attempts++;
          setTimeout(trySave, 1000 * attempts);
        } else {
          console.error('Max retries reached, queuing marker offline:', position.toString());
          marker.setMap(map);
          alertQueue.push(alertData);
          hazardMarkers.push({ marker, timestamp, type, _id: null });
          alertMarkers.set(null, marker);
          console.timeEnd(timerName);
          showToastMessage('Failed to save alert to server, queued offline.', 7000);
        }
      });
  }
  trySave();
  return marker;
}

function addMarkerFromDB(alert) {
  if (!window.google || !google.maps) {
    console.error('Google Maps API not loaded yet');
    return;
  }
  if (alertMarkers.has(alert._id)) return;
  const position = new google.maps.LatLng(alert.location.coordinates[1], alert.location.coordinates[0]);
  const marker = new google.maps.Marker({
    position: position,
    map: map,
    icon: {
      path: google.maps.SymbolPath.CIRCLE,
      fillColor: alert.type === 'Hazard' ? '#e74c3c' : '#f1c40f',
      fillOpacity: 1,
      strokeWeight: 2,
      strokeColor: '#ffffff',
      scale: 10
    },
    title: `${alert.type} Alert: ${alert.notes || 'No notes'}`
  });
  hazardMarkers.push({ marker, timestamp: alert.createdAt, type: alert.type, _id: alert._id, user: alert.user });
  alertMarkers.set(alert._id, marker);
  console.log(`${alert.type} marker loaded from DB with ID: ${alert._id} at:`, position.toString(), 'at', new Date(alert.createdAt).toLocaleString());
}

function cleanExpiredMarkers() {
  const now = Date.now();
  const threeHours = 3 * 60 * 60 * 1000;
  const expired = hazardMarkers.filter(hazard => now - hazard.timestamp > threeHours);
  expired.forEach(hazard => {
    if (alertMarkers.has(hazard._id || null)) {
      alertMarkers.get(hazard._id || null).setMap(null);
      alertMarkers.delete(hazard._id || null);
      if (hazard._id) {
        console.log(`Expired ${hazard.type} marker removed from map with ID: ${hazard._id}`);
      }
    }
  });
  hazardMarkers = hazardMarkers.filter(hazard => now - hazard.timestamp <= threeHours);
  allAlerts = allAlerts.filter(alert => now - new Date(alert.createdAt).getTime() <= threeHours);
  updateAlertTable();
}

function fetchAlerts() {
  if (!window.google || !google.maps) {
    console.error('Google Maps API not loaded yet, deferring alert fetch');
    setTimeout(fetchAlerts, 1000);
    return;
  }
  const token = localStorage.getItem('token');
  if (!token || !currentUser) {
    console.warn('No token or user available, skipping alert fetch');
    showToastMessage('Please log in to view alerts.', 5000);
    logout();
    return;
  }
  fetchWithTokenRefresh(`${BASE_URL}/api/map/all-alerts`, {
    headers: { 'Authorization': `Bearer ${token}` }
  })
    .then(response => {
      if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
      return response.json();
    })
    .then(alerts => {
      console.log('Raw API response for alerts:', JSON.stringify(alerts, null, 2));
      // Deduplicate alerts by _id
      const uniqueAlerts = [];
      const seenIds = new Set();
      alerts.forEach(alert => {
        if (!seenIds.has(alert._id)) {
          seenIds.add(alert._id);
          uniqueAlerts.push(alert);
        }
      });
      allAlerts = uniqueAlerts.map(alert => {
        const userLoc = new google.maps.LatLng(userLocation.lat, userLocation.lng);
        const alertLoc = new google.maps.LatLng(alert.location.coordinates[1], alert.location.coordinates[0]);
        const distance = window.google && google.maps && google.maps.geometry && google.maps.geometry.spherical
          ? google.maps.geometry.spherical.computeDistanceBetween(userLoc, alertLoc) / 1609.34
          : 0;
        return {
          ...alert,
          locationStr: `[${alert.location.coordinates[1].toFixed(6)}, ${alert.location.coordinates[0].toFixed(6)}]`,
          distance: distance
        };
      }).filter(alert => alert.distance <= 30);
      console.log('Fetched and deduplicated alerts:', JSON.stringify(allAlerts, null, 2));
      allAlerts.forEach(alert => addMarkerFromDB(alert));
      updateAlertTable();
      populateUserFilter();
      checkHazardsOnRoute();
    })
    .catch(err => {
      console.error('Failed to fetch alerts:', err.message);
      showToastMessage(`Failed to fetch alerts: ${err.message}`, 7000);
      if (err.message.includes('User not found') || err.message.includes('Invalid token')) {
        logout();
      }
    });
}

function checkUsernameAvailability(username) {
  return fetch(`${BASE_URL}/api/auth/check-availability`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username })
  })
    .then(response => {
      if (!response.ok) throw new Error('Availability check failed');
      return response.json();
    })
    .then(data => {
      if (data.errors?.username) {
        throw new Error(data.errors.username);
      }
      return data.available;
    })
    .catch(err => {
      console.error('Username availability check error:', err.message);
      throw err;
    });
}

function fetchUserProfile() {
  if (!currentUser) {
    console.warn('No current user, skipping profile fetch');
    showToastMessage('Please log in to view profile.', 5000);
    logout();
    return;
  }
  const token = localStorage.getItem('token');
  if (!token) {
    console.warn('No token available, skipping user profile fetch');
    showToastMessage('Please log in to view profile.', 5000);
    logout();
    return;
  }
  fetchWithTokenRefresh(`${BASE_URL}/api/auth/user/${currentUser.username}`, {
    headers: { 'Authorization': `Bearer ${token}` }
  })
    .then(response => {
      if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
      return response.json();
    })
    .then(data => {
      userProfile = data;
      currentUser = { ...currentUser, id: data._id };
      console.log('Fetched user profile and updated currentUser:', { userProfile, currentUser });
      updateProfileDisplay();
      updateEditProfileForm();
    })
    .catch(err => {
      console.error('Failed to fetch user profile:', err.message);
      showToastMessage(`Failed to fetch profile: ${err.message}`, 7000);
      if (err.message.includes('User not found') || err.message.includes('Invalid token')) {
        logout();
      }
    });
}

function updateProfileDisplay() {
  if (!accountInfo) {
    console.error('accountInfo element not found in DOM');
    return;
  }
  const nameEl = document.getElementById('account-name');
  const usernameEl = document.getElementById('account-username');
  const emailEl = document.getElementById('account-email');
  const ageEl = document.getElementById('account-age');
  const dobEl = document.getElementById('account-dob');
  const locationEl = document.getElementById('account-location');
  if (nameEl) nameEl.textContent = `Name: ${userProfile.name || 'Unknown'}`;
  if (usernameEl) usernameEl.textContent = `Username: ${userProfile.username || 'Unknown'}`;
  if (emailEl) emailEl.textContent = `Email: ${userProfile.email || 'Not Provided'}`;
  if (ageEl) ageEl.textContent = `Age: ${userProfile.age || 'Not Provided'}`;
  if (dobEl) dobEl.textContent = `DOB: ${userProfile.dob ? new Date(userProfile.dob).toLocaleDateString('en-US', { month: '2-digit', day: '2-digit', year: 'numeric' }) : 'Not Provided'}`;
  if (locationEl) locationEl.textContent = `Location: ${userProfile.location || 'Not Provided'}`;
  if (!accountInfo.querySelector('.logout-btn')) {
    const logoutButton = document.createElement('button');
    logoutButton.textContent = 'Logout';
    logoutButton.className = 'logout-btn';
    logoutButton.addEventListener('click', () => {
      logout();
      window.location.href = '/';
    });
    accountInfo.appendChild(logoutButton);
  }
}

function updateEditProfileForm() {
  const editName = document.getElementById('edit-name');
  const editUsername = document.getElementById('edit-username');
  const editEmail = document.getElementById('edit-email');
  const editAge = document.getElementById('edit-age');
  const editDob = document.getElementById('edit-dob');
  const editLocation = document.getElementById('edit-location');
  if (editName) editName.value = userProfile.name || '';
  if (editUsername) editUsername.value = userProfile.username || '';
  if (editEmail) editEmail.value = userProfile.email || '';
  if (editAge) editAge.value = userProfile.age || '';
  if (editDob) editDob.value = userProfile.dob ? new Date(userProfile.dob).toLocaleDateString('en-US', { month: '2-digit', day: '2-digit', year: 'numeric' }) : '';
  if (editLocation) editLocation.value = userProfile.location || '';
}

function updateAlertTable() {
  const table = document.getElementById('alert-table');
  if (!table) {
    console.error('Alert table not found in DOM');
    return;
  }
  const typeFilter = document.getElementById('alert-type-filter')?.value || '';
  const userFilter = document.getElementById('alert-user-filter')?.value || '';
  let filteredAlerts = allAlerts.filter(alert => {
    const matchesType = !typeFilter || alert.type === typeFilter;
    const matchesUser = !userFilter || (alert.user && alert.user.username === userFilter);
    return matchesType && matchesUser && (currentTab === 'alerts' ? true : alert.user?._id.toString() === userProfile._id?.toString());
  });
  const startIdx = (currentPage - 1) * ALERTS_PER_PAGE;
  const endIdx = startIdx + ALERTS_PER_PAGE;
  const paginatedAlerts = filteredAlerts.slice(startIdx, endIdx);
  table.innerHTML = `
    <tr>
      <th>Type</th>
      <th>Notes</th>
      <th>Location</th>
      <th>Timestamp</th>
      <th>User</th>
      <th>Action</th>
    </tr>
  `;
  paginatedAlerts.forEach(alert => {
    const isOwnAlert = alert.user?._id.toString() === userProfile._id?.toString();
    const isAdmin = userProfile.email === 'imhoggbox@gmail.com';
    const canDelete = isOwnAlert || isAdmin;
    const userDisplay = alert.user?.username || 'Anonymous';
    console.log('Processing alert:', { alertId: alert._id, isOwnAlert, isAdmin, canDelete, userDisplay });
    const row = document.createElement('tr');
    row.innerHTML = `
      <td>${alert.type}</td>
      <td>${alert.notes || 'None'}</td>
      <td>${alert.locationStr}</td>
      <td>${new Date(alert.createdAt).toLocaleString()}</td>
      <td>${userDisplay}</td>
      <td>${canDelete ? `<button class="delete-btn" onclick="removeAlert('${alert._id}')">×</button>` : ''}</td>
    `;
    table.appendChild(row);
  });
  updatePagination(filteredAlerts.length);
}

function updatePagination(totalAlerts) {
  const pagination = document.getElementById('alert-pagination');
  if (!pagination) {
    console.error('Pagination element not found in DOM');
    return;
  }
  pagination.innerHTML = '';
  const totalPages = Math.ceil(totalAlerts / ALERTS_PER_PAGE);
  for (let i = 1; i <= totalPages; i++) {
    const button = document.createElement('button');
    button.textContent = i;
    button.className = i === currentPage ? 'active' : '';
    button.addEventListener('click', () => {
      currentPage = i;
      updateAlertTable();
    });
    pagination.appendChild(button);
  }
  const prevButton = document.createElement('button');
  prevButton.textContent = '<';
  prevButton.addEventListener('click', () => {
    if (currentPage > 1) {
      currentPage--;
      updateAlertTable();
    }
  });
  pagination.insertBefore(prevButton, pagination.firstChild);
  const nextButton = document.createElement('button');
  nextButton.textContent = '>';
  nextButton.addEventListener('click', () => {
    if (currentPage < totalPages) {
      currentPage++;
      updateAlertTable();
    }
  });
  pagination.appendChild(nextButton);
}

function populateUserFilter() {
  const userFilter = document.getElementById('alert-user-filter');
  if (!userFilter) {
    console.error('User filter element not found in DOM');
    return;
  }
  const uniqueUsers = [...new Set(allAlerts.map(alert => alert.user?.username).filter(Boolean))];
  userFilter.innerHTML = '<option value="">All Users</option>';
  uniqueUsers.forEach(user => {
    const option = document.createElement('option');
    option.value = user;
    option.textContent = user;
    userFilter.appendChild(option);
  });
}

function fetchWithTokenRefresh(url, options = {}) {
  const token = localStorage.getItem('token');
  if (!token) {
    console.error('No token available');
    logout();
    return Promise.reject(new Error('No token available'));
  }
  return fetch(url, {
    ...options,
    headers: { ...options.headers, 'Authorization': `Bearer ${token}` }
  }).then(response => {
    if (response.status === 403 || response.status === 401) {
      console.warn('Token might be expired or invalid, attempting refresh');
      return refreshToken().then(newToken => {
        if (newToken) {
          localStorage.setItem('token', newToken);
          options.headers['Authorization'] = `Bearer ${newToken}`;
          return fetch(url, options);
        }
        return Promise.reject(new Error('Refresh failed, no new token'));
      }).catch(err => {
        console.error('Refresh failed:', err);
        logout();
        return Promise.reject(err);
      });
    }
    return response;
  });
}

function refreshToken() {
  const refreshToken = localStorage.getItem('refreshToken');
  if (!refreshToken) {
    console.error('No refresh token available, prompting re-login');
    logout();
    return Promise.resolve(null);
  }
  return fetch(`${BASE_URL}/api/auth/refresh`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refreshToken })
  })
    .then(response => {
      if (!response.ok) throw new Error(`Refresh failed with status: ${response.status}`);
      return response.json();
    })
    .then(data => data.token || null)
    .catch(err => {
      console.error('Token refresh failed:', err);
      logout();
      return Promise.resolve(null);
    });
}

function login(username, password, loginBtn, loginUsername, loginPassword) {
  if (!username || !password) {
    console.error('Login attempt with missing username or password:', { username, password });
    showToastMessage('Username or email and password are required.', 5000);
    return;
  }
  const trimmedUsername = username.trim();
  const trimmedPassword = password.trim();
  console.log('Sending login request with:', { username: trimmedUsername, password: '[provided]' });
  fetch(`${BASE_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: trimmedUsername, password: trimmedPassword })
  })
    .then(response => {
      console.log('Login response status:', response.status);
      if (!response.ok) return response.json().then(data => { throw new Error(data.msg || 'Login failed') });
      return response.json();
    })
    .then(data => {
      console.log('Login response data:', data);
      if (!data.token) throw new Error('No token in login response');
      localStorage.setItem('token', data.token);
      if (data.refreshToken) {
        localStorage.setItem('refreshToken', data.refreshToken);
      } else {
        console.warn('No refreshToken in response, proceeding with token only');
      }
      currentUser = { username: data.username, id: data.userId };
      console.log('Logged in user:', currentUser);
      if (loginBtn && loginUsername && loginPassword) {
        loginBtn.style.display = 'none';
        loginUsername.value = '';
        loginPassword.value = '';
      }
      const loginScreen = document.getElementById('login-screen');
      if (loginScreen) loginScreen.style.display = 'none';
      initializeMapAfterLogin();
    })
    .catch(err => {
      console.error('Login error:', err.message);
      showToastMessage(`Login failed: ${err.message}`, 7000);
    });
}

function logout() {
  localStorage.removeItem('token');
  localStorage.removeItem('refreshToken');
  currentUser = null;
  userProfile = { name: '', username: '', email: '', age: '', dob: null, location: '', _id: null, lastUsernameChange: null };
  ignoredHazards = [];
  allAlerts = [];
  hazardMarkers.forEach(h => h.marker.setMap(null));
  hazardMarkers = [];
  alertMarkers.clear();
  const loginScreen = document.getElementById('login-screen');
  const map = document.getElementById('map');
  const profileHud = document.getElementById('profile-hud');
  const settingsHud = document.getElementById('settings-hud');
  if (loginScreen) loginScreen.style.display = 'flex';
  if (map) map.style.display = 'none';
  if (profileHud && profileHud.classList) profileHud.classList.remove('active');
  if (settingsHud && settingsHud.classList) settingsHud.classList.remove('active');
  if (profileHud) profileHud.style.display = 'none';
  console.log('Logged out, resetting to login screen');
}

function alertAtCurrentLocation() {
  const alertType = document.getElementById('alertType');
  if (!alertType) {
    console.error('alertType element not found');
    showToastMessage('Error: Alert type not found.', 7000);
    return;
  }
  const type = alertType.value;
  if (!currentUser) {
    console.warn('No current user, cannot post alert');
    showToastMessage('Please log in to post alerts.', 5000);
    logout();
    return;
  }
  if (navigator.geolocation) {
    console.log('Requesting geolocation for current location alert');
    navigator.geolocation.getCurrentPosition(
      (position) => {
        const { latitude, longitude } = position.coords;
        userLocation = { lat: latitude, lng: longitude };
        lastLocationUpdate = Date.now();
        console.log('Current location retrieved:', userLocation);
        addAlert(type, '', new google.maps.LatLng(latitude, longitude)).then(() => {
          const detailedAlertBox = document.getElementById('detailedAlertBox');
          if (detailedAlertBox) {
            detailedAlertBox.classList.remove('active');
            detailedAlertBox.style.display = 'none';
          }
          console.log('Alert posted at current location:', userLocation);
        }).catch(err => {
          console.error('Failed to post alert at current location:', err);
          showToastMessage('Failed to post alert at current location.', 7000);
        });
      },
      (err) => {
        console.error('Geolocation error for current location alert:', err);
        let errorMessage = 'Failed to get current location. ';
        if (err.code === 1) {
          errorMessage += 'Location permission denied. Please enable location services.';
        } else if (err.code === 2) {
          errorMessage += 'Location unavailable. Using last known location.';
        } else if (err.code === 3) {
          errorMessage += 'Location request timed out. Using last known location.';
        } else {
          errorMessage += 'An unknown error occurred. Using last known location.';
        }
        showToastMessage(errorMessage, 7000);
        const fallbackLocation = userLocation.lat && userLocation.lng
          ? new google.maps.LatLng(userLocation.lat, userLocation.lng)
          : new google.maps.LatLng(33.0891264, -83.2372736);
        console.log('Using fallback location for alert:', fallbackLocation.toString());
        addAlert('Hazard', '', fallbackLocation).then(() => {
          const detailedAlertBox = document.getElementById('detailedAlertBox');
          if (detailedAlertBox) {
            detailedAlertBox.classList.remove('active');
            detailedAlertBox.style.display = 'none';
          }
          console.log('Alert posted with fallback location');
        }).catch(err => {
          console.error('Failed to post alert with fallback:', err);
          showToastMessage('Failed to post alert with fallback.', 7000);
        });
      },
      { maximumAge: 10000, timeout: 30000, enableHighAccuracy: true }
    );
  } else {
    console.error('Geolocation unavailable');
    showToastMessage('Geolocation not supported. Using default location.', 7000);
    const defaultLocation = new google.maps.LatLng(33.0891264, -83.2372736);
    console.log('Using default location for alert:', defaultLocation.toString());
    addAlert('Hazard', '', defaultLocation).then(() => {
      const detailedAlertBox = document.getElementById('detailedAlertBox');
      if (detailedAlertBox) {
        detailedAlertBox.classList.remove('active');
        detailedAlertBox.style.display = 'none';
      }
      console.log('Alert posted with default location');
    }).catch(err => {
      console.error('Failed to post alert with default:', err);
      showToastMessage('Failed to post alert with default.', 7000);
    });
  }
}

function initializeMapAfterLogin() {
  const mapElement = document.getElementById('map');
  if (mapElement) mapElement.style.display = 'block';
  if (window.google && google.maps) {
    window.initMap();
  } else {
    const script = document.createElement('script');
    script.src = `https://maps.googleapis.com/maps/api/js?key=${GOOGLE_MAPS_API_KEY}&libraries=places,geometry&callback=initMap&v=${VERSION}`;
    script.async = true;
    script.defer = true;
    document.head.appendChild(script);
    script.onload = () => window.initMap();
    script.onerror = () => console.error('Google Maps API failed to load');
  }
}

window.removeAlert = function(alertId) {
  const token = localStorage.getItem('token');
  if (!token) {
    console.error('No token available, cannot remove alert');
    showToastMessage('Please log in to remove alerts.', 7000);
    return;
  }
  fetchWithTokenRefresh(`${BASE_URL}/api/map/alert/${alertId}`, {
    method: 'DELETE',
    headers: { 'Authorization': `Bearer ${token}` }
  })
    .then(response => {
      if (!response.ok) throw new Error(`Failed to delete alert: ${response.status}`);
      return response.json();
    })
    .then(() => {
      console.log('Alert removed successfully:', alertId);
      showToastMessage('Alert removed successfully.', 5000);
      fetchAlerts();
    })
    .catch(err => {
      console.error('Error removing alert:', err.message);
      showToastMessage(`Failed to remove alert: ${err.message}`, 7000);
      if (err.message.includes('User not found') || err.message.includes('Invalid token')) {
        logout();
      }
    });
};

window.initMap = function() {
  console.time('Map initialization');
  if (!window.google || !google.maps) {
    console.error('Google Maps API failed to load');
    setTimeout(window.initMap, 1000);
    return;
  }
  const token = localStorage.getItem('token');
  const loginScreen = document.getElementById('login-screen');
  const mapElement = document.getElementById('map');
  if (!token) {
    if (loginScreen) loginScreen.style.display = 'flex';
    if (mapElement) mapElement.style.display = 'none';
    return;
  }
  try {
    if (typeof jwt_decode === 'function') {
      const decoded = jwt_decode(token);
      if (decoded && decoded.username) {
        currentUser = { username: decoded.username, id: decoded._id || null };
        console.log('Decoded token user:', currentUser);
      } else {
        throw new Error('Invalid token payload');
      }
    } else {
      console.warn('jwt_decode not available, skipping token validation');
    }
    if (loginScreen) loginScreen.style.display = 'none';
    if (mapElement) mapElement.style.display = 'block';
    fetchUserProfile();
    fetchAlerts();
  } catch (err) {
    console.error('Token validation error:', err);
    if (loginScreen) loginScreen.style.display = 'flex';
    if (mapElement) mapElement.style.display = 'none';
    localStorage.removeItem('token');
    localStorage.removeItem('refreshToken');
    return;
  }
  map = new google.maps.Map(mapElement, {
    center: userLocation,
    zoom: 13,
    styles: [
      { elementType: 'geometry', stylers: [{ color: '#2c3e50' }] },
      { elementType: 'labels.text.stroke', stylers: [{ color: '#1f2a38' }] },
      { elementType: 'labels.text.fill', stylers: [{ color: '#ecf0f1' }] },
      { featureType: 'administrative', elementType: 'geometry.stroke', stylers: [{ color: '#1f2a38' }] },
      { featureType: 'road', elementType: 'geometry', stylers: [{ color: '#34495e' }] },
      { featureType: 'road', elementType: 'labels', stylers: [{ visibility: 'on', color: '#ecf0f1' }] }
    ],
    disableDefaultUI: true,
    fullscreenControl: false,
    mapTypeControl: false
  });
  if (!map) {
    console.error('Map initialization failed');
    return;
  }
  autocompleteService = new google.maps.places.AutocompleteService();
  placesService = new google.maps.places.PlacesService(map);
  directionsService = new google.maps.DirectionsService();
  directionsRenderer = new google.maps.DirectionsRenderer({ map: map, suppressMarkers: true });
  console.log('Map, Directions, and Places initialized');
  mapReadyResolve();
  if (navigator.geolocation) {
    navigator.geolocation.watchPosition(
      (position) => {
        const now = Date.now();
        userLocation = { lat: position.coords.latitude, lng: position.coords.longitude };
        lastLocationUpdate = now;
        console.log('WatchPosition updated user location:', userLocation, 'Time:', now);
        if (map) {
          const currentPos = new google.maps.LatLng(position.coords.latitude, position.coords.longitude);
          if (liveLocationMarker) liveLocationMarker.setMap(null);
          const canvas = document.createElement('canvas');
          const ctx = canvas.getContext('2d');
          if (ctx) {
            canvas.width = 40;
            canvas.height = 40;
            ctx.shadowBlur = 4;
            ctx.shadowColor = 'rgba(0, 0, 0, 0.5)';
            ctx.shadowOffsetX = 2;
            ctx.shadowOffsetY = 2;
            ctx.save();
            ctx.translate(20, 20);
            let currentHeading = position.coords.heading || 0;
            ctx.rotate(currentHeading * Math.PI / 180);
            ctx.translate(-20, -20);
            ctx.fillStyle = '#00bcd4';
            ctx.strokeStyle = '#000000';
            ctx.lineWidth = 2;
            ctx.beginPath();
            ctx.moveTo(20, 8);
            ctx.lineTo(8, 32);
            ctx.lineTo(32, 32);
            ctx.closePath();
            ctx.fill();
            ctx.stroke();
            ctx.restore();
            const imageUrl = canvas.toDataURL();
            if (imageUrl.startsWith('data:image')) {
              liveLocationMarker = new google.maps.Marker({
                position: currentPos,
                map: map,
                icon: { url: imageUrl, scaledSize: new google.maps.Size(40, 40) },
                title: 'Live Location'
              });
              console.log('Triangle marker set at:', currentPos.toString());
            } else {
              liveLocationMarker = new google.maps.Marker({
                position: currentPos,
                map: map,
                icon: {
                  path: google.maps.SymbolPath.CIRCLE,
                  fillColor: '#00bcd4',
                  fillOpacity: 1,
                  strokeWeight: 2,
                  strokeColor: '#000000',
                  scale: 10
                },
                title: 'Live Location (Fallback)'
              });
              console.log('Using fallback circle at:', currentPos.toString());
            }
          } else {
            liveLocationMarker = new google.maps.Marker({
              position: currentPos,
              map: map,
              icon: {
                path: google.maps.SymbolPath.CIRCLE,
                fillColor: '#00bcd4',
                fillOpacity: 1,
                strokeWeight: 2,
                strokeColor: '#000000',
                scale: 10
              },
              title: 'Live Location (Fallback)'
            });
            console.log('Using fallback circle at:', currentPos.toString());
          }
        }
        if (isNavigating && routePath.length > 0 && position.coords.heading !== undefined) {
          provideVoiceNavigation(position.coords);
        }
        checkHazardsOnRoute();
      },
      (err) => console.warn('WatchPosition error:', err),
      { maximumAge: 0, timeout: 10000, enableHighAccuracy: true }
    );
    navigator.geolocation.getCurrentPosition(
      (position) => {
        userLocation = { lat: position.coords.latitude, lng: position.coords.longitude };
        lastLocationUpdate = Date.now();
        console.log('Initial user location:', userLocation);
        if (map) map.setCenter(userLocation);
      },
      (err) => console.warn('Initial geolocation failed, using fallback:', err, userLocation),
      { maximumAge: 0, timeout: 10000, enableHighAccuracy: true }
    );
  }
  console.timeEnd('Map initialization');
};

window.addEventListener('DOMContentLoaded', () => {
  console.time('DOM initialization');
  console.log('DOM fully loaded at:', new Date().toLocaleTimeString());
  const hud = document.getElementById('hud');
  const controlHud = document.getElementById('control-hud');
  const speedLimit = document.getElementById('speedLimit');
  const currentSpeed = document.getElementById('currentSpeed');
  const eta = document.getElementById('eta');
  const dta = document.getElementById('dta');
  const time = document.getElementById('time');
  const navAddress = document.getElementById('navAddress');
  const addAlertBtn = document.getElementById('addAlert');
  const navOverlay = document.getElementById('navOverlay');
  const recentLocations = document.getElementById('recentLocations');
  const suggestions = document.getElementById('suggestions');
  const closeOverlay = document.getElementById('closeOverlay');
  const cancelBtn = document.querySelector('#control-hud .cancel-btn');
  const recenterBtn = document.querySelector('#control-hud .recenter-btn');
  const muteBtn = document.querySelector('#control-hud .mute-btn');
  const hazardBtn = document.querySelector('#control-hud .hazard-btn');
  const toolsHud = document.getElementById('tools-hud');
  const micButton = document.querySelector('.mic-button');
  const voiceOverlay = document.getElementById('voiceOverlay');
  const pulsator = document.querySelector('.pulsator');
  const closeVoiceOverlay = document.getElementById('closeVoiceOverlay');
  const voiceInstruction = document.getElementById('voiceInstruction');
  const detailedAlertBtn = document.getElementById('detailedAlert-btn');
  const detailedAlertBox = document.getElementById('detailedAlertBox');
  const closeDetailedAlertBtn = document.querySelector('#detailedAlertBox .close-btn');
  const alertType = document.getElementById('alertType');
  const alertNotes = document.getElementById('alertNotes');
  const clickLocationBtn = document.getElementById('click-location-alert');
  const alertCurrentBtn = document.getElementById('alert-current-location');
  const locationDisplay = document.getElementById('location-display');
  const selectedLocation = document.getElementById('selected-location');
  const postAlertBtn = document.getElementById('post-alert');
  const cancelAlertBtn = document.getElementById('cancel-alert');
  const toastMessage = document.getElementById('toast-message');
  const profileBtn = document.getElementById('profile-btn');
  const profileHud = document.getElementById('profile-hud');
  const closeBtn = document.querySelector('#profile-hud .close-btn');
  accountInfo = document.querySelector('.account-info');
  editProfile = document.querySelector('.edit-profile');
  alertsTab = document.querySelector('.alerts');
  tabButtons = document.querySelectorAll('.tab-button');
  const saveProfileBtn = document.getElementById('save-profile-btn');
  const settingsBtn = document.getElementById('settings-btn');
  const settingsHud = document.getElementById('settings-hud');
  const closeSettings = document.getElementById('closeSettings');
  const loginBtn = document.getElementById('login-btn');
  const loginUsername = document.getElementById('login-username');
  const loginPassword = document.getElementById('login-password');
  const reroutePrompt = document.getElementById('reroutePrompt');
  const rerouteYes = document.getElementById('rerouteYes');
  const rerouteNo = document.getElementById('rerouteNo');
  console.log('addAlert button in JS:', addAlertBtn ? 'found' : 'not found');
  if (!addAlertBtn) console.log('addAlert button not found in DOM');
  else console.log('addAlert button ready');

  // Ensure overlays are hidden on load
  if (navOverlay) {
    navOverlay.style.display = 'none';
    console.log('navOverlay set to hidden on load');
  } else {
    console.error('navOverlay not found on DOM load');
  }
  if (voiceOverlay) {
    voiceOverlay.style.display = 'none';
    console.log('voiceOverlay set to hidden on load');
  } else {
    console.error('voiceOverlay not found on DOM load');
  }
  if (detailedAlertBox) {
    detailedAlertBox.style.display = 'none';
    detailedAlertBox.style.left = '50%';
    detailedAlertBox.style.top = '50%';
    console.log('detailedAlertBox set to hidden on load, element:', detailedAlertBox);
  } else {
    console.error('detailedAlertBox not found on DOM load');
  }
  if (profileHud) {
    profileHud.style.display = 'none';
    console.log('profileHud set to hidden on load');
  } else {
    console.error('profileHud not found on DOM load');
  }
  if (settingsHud) {
    settingsHud.style.display = 'none';
    console.log('settingsHud set to hidden on load');
  } else {
    console.error('settingsHud not found on DOM load');
  }
  if (reroutePrompt) {
    reroutePrompt.style.display = 'none';
    console.log('reroutePrompt set to hidden on load');
  } else {
    console.error('reroutePrompt not found on DOM load');
  }

  // Handle screen orientation change
  window.addEventListener('orientationchange', () => {
    console.log('Orientation changed to:', window.orientation || 'not supported');
    if ((window.orientation === 90 || window.orientation === -90) && window.orientation !== undefined) {
      document.body.classList.add('landscape');
      document.body.classList.remove('portrait');
    } else {
      document.body.classList.add('portrait');
      document.body.classList.remove('landscape');
    }
  });

  // Initialize Socket.IO with retry logic
  function loadSocketIOScript() {
    return new Promise((resolve, reject) => {
      if (window.io) {
        resolve();
        return;
      }
      const script = document.createElement('script');
      script.src = `${BASE_URL}/socket.io/socket.io.js`;
      script.async = true;
      script.onload = () => {
        console.log('Socket.IO script loaded successfully');
        resolve();
      };
      script.onerror = () => {
        console.error('Failed to load Socket.IO script');
        reject(new Error('Socket.IO script failed to load'));
      };
      document.head.appendChild(script);
    });
  }

  function connectSocket() {
    loadSocketIOScript()
      .then(() => {
        socket = window.io(BASE_URL, { reconnectionAttempts: 5, reconnectionDelay: 1000 });
        console.log('Socket.IO connected to:', BASE_URL);
        socket.on('connect', () => {
          console.log('Socket.IO connection established');
          socket.on('hazard', (data) => {
            if (map && !alertMarkers.has(data._id)) {
              addMarkerFromDB(data);
              fetchAlerts();
            }
          });
          socket.on('detailedAlert', (data) => {
            if (map && !alertMarkers.has(data._id)) {
              addMarkerFromDB(data);
              fetchAlerts();
            }
          });
          socket.on('alert', (data) => {
            if (map) {
              new google.maps.Marker({
                position: { lat: data.location.coordinates[1], lng: data.location.coordinates[0] },
                map: map,
                title: data.type
              });
            }
          });
          socket.on('alertRemoved', (data) => {
            if (alertMarkers.has(data._id)) {
              alertMarkers.get(data._id).setMap(null);
              alertMarkers.delete(data._id);
              hazardMarkers = hazardMarkers.filter(h => h._id !== data._id);
              allAlerts = allAlerts.filter(a => a._id !== data._id);
              updateAlertTable();
            }
            console.log('Alert removed via socket:', data._id);
          });
          socket.on('locationUpdate', (data) => {
            if (map) {
              new google.maps.Marker({
                position: { lat: data.latitude, lng: data.longitude },
                map: map,
                title: 'User Location'
              });
            }
          });
        });
        socket.on('connect_error', (err) => {
          console.warn('Socket.IO connection error:', err.message);
        });
      })
      .catch(err => {
        console.warn('Socket.IO failed to load, retrying in 5 seconds:', err);
        setTimeout(connectSocket, 5000);
      });
  }
  connectSocket();

  function getCurrentTime() {
    return new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
  }

  function getEstimatedArrivalTime(etaMinutes) {
    const now = new Date();
    now.setMinutes(now.getMinutes() + etaMinutes);
    return now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
  }

  function showOverlay() {
    console.time('Show overlay');
    console.log('Showing overlay');
    if (navOverlay) {
      navOverlay.style.display = 'block';
      recentLocations.innerHTML = '';
      recentDestinations.forEach(dest => {
        const item = document.createElement('div');
        item.className = 'recent-item';
        item.textContent = dest;
        item.addEventListener('click', () => {
          if (navAddress) navAddress.value = dest;
          startNavigation(dest);
          if (navOverlay) navOverlay.style.display = 'none';
        });
        recentLocations.appendChild(item);
      });
    } else {
      console.error('navOverlay not found');
    }
    console.timeEnd('Show overlay');
  }

  async function startNavigation(address) {
    console.time('Start navigation');
    await mapReady;
    isNavigating = true;
    console.log('Navigation started, setting isNavigating to true');
    if (hud) hud.classList.add('navigating');
    if (controlHud) controlHud.classList.add('navigating');
    console.log('HUD classes updated:', { hudClass: hud?.className, controlHudClass: controlHud?.className });
    routePath = [];
    ignoredHazards = [];
    const destination = await geocodeWithGoogle(address);
    if (destination) {
      currentDestination = destination;
      const position = userLocation;
      console.log(`Navigating from [${position.lat}, ${position.lng}] to [${destination[0]}, ${destination[1]}]`);
      if (map && !isNaN(position.lat) && !isNaN(position.lng)) {
        try {
          await updateRoute([position.lat, position.lng], destination);
          if (!isMuted && 'speechSynthesis' in window && femaleVoice) {
            const utterance = new SpeechSynthesisUtterance('Navigation started. Follow the route.');
            utterance.voice = femaleVoice;
            utterance.lang = 'en-US';
            utterance.volume = 1.0;
            window.speechSynthesis.speak(utterance);
            console.log('Navigation voice test triggered with:', femaleVoice.name);
          } else if (!femaleVoice) {
            console.warn('No female voice available, skipping speech');
          }
          checkHazardsOnRoute();
        } catch (err) {
          console.error('Route update failed:', err);
        }
      } else {
        console.error('Invalid coordinates, using fallback:', userLocation);
        await updateRoute([userLocation.lat, userLocation.lng], destination);
        checkHazardsOnRoute();
      }
    } else {
      alert('Could not geocode address. Please check your internet connection.');
      isNavigating = false;
      if (hud) hud.classList.remove('navigating');
      if (controlHud) controlHud.classList.remove('navigating');
    }
    console.timeEnd('Start navigation');
  }

  function stopNavigation() {
    console.log('Stopping navigation, attempting to clear route');
    isNavigating = false;
    routePath = [];
    currentDestination = null;
    ignoredHazards = [];
    if (hud) hud.classList.remove('navigating');
    if (controlHud) controlHud.classList.remove('navigating');
    if (routePolyline) {
      routePolyline.setMap(null);
      routePolyline = null;
    }
    if (directionsRenderer) {
      directionsRenderer.setMap(null);
    }
    if (eta) eta.textContent = 'N/A';
    if (dta) dta.textContent = 'N/A';
    if (time) time.textContent = '0:00';
  }

  function recenterMap() {
    if (navigator.geolocation && map && isNavigating) {
      navigator.geolocation.getCurrentPosition(
        (position) => {
          const { latitude, longitude } = position.coords;
          const currentPos = new google.maps.LatLng(latitude, longitude);
          if (map) map.setCenter(currentPos);
          if (routePath.length > 0) {
            const closestPoint = findClosestPointOnRoute(currentPos, routePath);
            const nextPointIndex = routePath.findIndex((point, index) => index > closestPoint.index && point) || 1;
            if (nextPointIndex > 0 && nextPointIndex < routePath.length) {
              const nextPoint = routePath[nextPointIndex];
              if (map) map.setHeading(google.maps.geometry.spherical.computeHeading(currentPos, nextPoint));
            }
          }
          console.log('Map recentered at:', currentPos.toString());
        },
        (err) => console.log('Recenter geolocation error:', err),
        { maximumAge: 0, timeout: 5000, enableHighAccuracy: true }
      );
    }
  }

  function startVoiceRecognition() {
    if (!('webkitSpeechRecognition' in window)) {
      alert('Voice recognition not supported in this browser.');
      return;
    }
    if (recognition) recognition.stop();
    recognition = new webkitSpeechRecognition();
    recognition.continuous = false;
    recognition.interimResults = false;
    recognition.lang = 'en-US';
    recognition.onstart = () => {
      console.log('Voice recognition started');
      if (voiceOverlay) voiceOverlay.style.display = 'flex';
      if (pulsator) pulsator.classList.add('active');
      if (voiceInstruction) voiceInstruction.textContent = 'Speak the address or location...';
    };
    recognition.onresult = (event) => {
      const transcript = event.results[0][0].transcript.trim();
      console.log('Voice input:', transcript);
      if (transcript) {
        if (navAddress) navAddress.value = transcript;
        stopVoiceRecognition();
        confirmVoiceInput(transcript);
      } else {
        if (voiceInstruction) voiceInstruction.textContent = 'No input detected, please try again...';
      }
    };
    recognition.onerror = (event) => {
      console.error('Voice recognition error:', event.error);
      if (voiceInstruction) voiceInstruction.textContent = `Error: ${event.error}. Please try again.`;
      stopVoiceRecognition();
    };
    recognition.onend = () => {
      if (voiceOverlay && voiceOverlay.style.display === 'flex' && !recognition) {
        if (voiceInstruction) voiceInstruction.textContent = 'Speak the address or location...';
      }
    };
    recognition.start();
    console.log('Recognition started, requesting microphone access');
  }

  function stopVoiceRecognition() {
    if (recognition) {
      recognition.stop();
      recognition = null;
      if (pulsator) pulsator.classList.remove('active');
      console.log('Voice recognition stopped');
    }
  }

  function confirmVoiceInput(transcript) {
    if ('speechSynthesis' in window && femaleVoice) {
      const utterance = new SpeechSynthesisUtterance(`You said ${transcript}. Is this correct?`);
      utterance.voice = femaleVoice;
      utterance.lang = 'en-US';
      window.speechSynthesis.speak(utterance);
      if (recognition) recognition.stop();
      recognition = new webkitSpeechRecognition();
      recognition.continuous = false;
      recognition.interimResults = false;
      recognition.lang = 'en-US';
      recognition.onstart = () => {
        if (voiceOverlay) voiceOverlay.style.display = 'flex';
        if (pulsator) pulsator.classList.add('active');
        if (voiceInstruction) voiceInstruction.textContent = 'Say "yes" or "no"...';
      };
      recognition.onresult = (event) => {
        const confirmation = event.results[0][0].transcript.toLowerCase().trim();
        console.log('Confirmation input:', confirmation);
        if (confirmation.includes('yes')) {
          startNavigation(transcript);
        } else if (confirmation.includes('no')) {
          if (voiceInstruction) voiceInstruction.textContent = 'Please try again...';
          const retryUtterance = new SpeechSynthesisUtterance('Please try again.');
          retryUtterance.voice = femaleVoice;
          window.speechSynthesis.speak(retryUtterance);
          setTimeout(() => startVoiceRecognition(), 1000);
        } else {
          if (voiceInstruction) voiceInstruction.textContent = 'Please say "yes" or "no"...';
          const promptUtterance = new SpeechSynthesisUtterance('Please say "yes" or "no".');
          promptUtterance.voice = femaleVoice;
          window.speechSynthesis.speak(promptUtterance);
          setTimeout(() => confirmVoiceInput(transcript), 1000);
        }
        stopVoiceRecognition();
      };
      recognition.onerror = (event) => {
        console.error('Confirmation error:', event.error);
        if (voiceInstruction) voiceInstruction.textContent = `Error: ${event.error}. Please try again.`;
        stopVoiceRecognition();
        setTimeout(() => confirmVoiceInput(transcript), 1000);
      };
      recognition.onend = () => {
        if (voiceOverlay && voiceOverlay.style.display === 'flex' && !recognition) {
          if (voiceInstruction) voiceInstruction.textContent = 'Say "yes" or "no"...';
        }
      };
      recognition.start();
    } else {
      alert('Text-to-speech not supported or no voice available in this browser.');
      startNavigation(transcript);
    }
  }

  function showDetailedAlertBox() {
    console.time('Show detailed alert box');
    console.log('Showing detailed alert box, element:', detailedAlertBox);
    if (detailedAlertBox) {
      console.log('Current class list:', detailedAlertBox.classList);
      detailedAlertBox.classList.add('active');
      detailedAlertBox.style.display = 'flex';
      detailedAlertBox.style.left = '50%';
      detailedAlertBox.style.top = '50%';
      console.log('Added active class, new class list:', detailedAlertBox.classList, 'display style:', window.getComputedStyle(detailedAlertBox).display);
      detailedAlertBox.style.opacity = '0';
      setTimeout(() => {
        detailedAlertBox.style.opacity = '1';
      }, 0);
      if (alertType) alertType.style.display = 'block';
      const alertTypeLabel = document.querySelector('#detailedAlertBox label[for="alertType"]');
      if (alertTypeLabel) alertTypeLabel.style.display = 'block';
      if (clickLocationBtn) clickLocationBtn.style.display = 'block';
      if (alertCurrentBtn) alertCurrentBtn.style.display = 'block';
      if (locationDisplay) locationDisplay.style.display = 'none';
      if (alertNotes) alertNotes.value = '';
      if (postAlertBtn) postAlertBtn.style.display = 'none';
      if (cancelAlertBtn) cancelAlertBtn.style.display = 'none';
      if (toastMessage) toastMessage.style.display = 'none';
    } else {
      console.error('detailedAlertBox element not found');
    }
    console.timeEnd('Show detailed alert box');
  }

  function addAlert(type, notes = '', position) {
    return new Promise((resolve, reject) => {
      console.time(`Add ${type} alert`);
      if (!position) {
        console.error('No position provided for alert, using default location');
        position = new google.maps.LatLng(33.0891264, -83.2372736);
      }
      if (!currentUser) {
        console.warn('No current user, cannot post alert');
        showToastMessage('Please log in to post alerts.', 5000);
        logout();
        reject(new Error('No authenticated user'));
        return;
      }
      addMarker(type, notes, position).then(() => {
        showToastMessage('Your alert has been posted.', 5000);
        console.timeEnd(`Add ${type} alert`);
        resolve();
      }).catch(err => {
        console.error('Failed to post alert:', err);
        showToastMessage('Failed to post alert.', 7000);
        console.timeEnd(`Add ${type} alert`);
        reject(err);
      });
    });
  }

  function addHazardMarker() {
    const now = Date.now();
    if (now - lastHazardTime < 1000) {
      console.log('Hazard add debounced, too soon');
      return;
    }
    lastHazardTime = now;
    console.log('Hazard button clicked, checking geolocation...');
    if (!currentUser) {
      console.warn('No current user, cannot post hazard');
      showToastMessage('Please log in to post alerts.', 5000);
      logout();
      return;
    }
    if (navigator.geolocation) {
      console.log('Requesting geolocation for hazard alert');
      navigator.geolocation.getCurrentPosition(
        (position) => {
          const { latitude, longitude } = position.coords;
          userLocation = { lat: latitude, lng: longitude };
          lastLocationUpdate = Date.now();
          console.log('Current location retrieved for hazard:', userLocation);
          addAlert('Hazard', '', new google.maps.LatLng(latitude, longitude)).then(() => {
            console.log('Hazard alert posted at:', userLocation);
          }).catch(err => {
            console.error('Failed to post hazard alert:', err);
            showToastMessage('Failed to post hazard alert.', 7000);
          });
        },
        (err) => {
          console.error('Geolocation error for hazard alert:', err);
          let errorMessage = 'Failed to get current location for hazard. ';
          if (err.code === 1) {
            errorMessage += 'Location permission denied. Please enable location services.';
          } else if (err.code === 2) {
            errorMessage += 'Location unavailable. Using last known location.';
          } else if (err.code === 3) {
            errorMessage += 'Location request timed out. Using last known location.';
          } else {
            errorMessage += 'An unknown error occurred. Using last known location.';
          }
          showToastMessage(errorMessage, 7000);
          const fallbackLocation = userLocation.lat && userLocation.lng
            ? new google.maps.LatLng(userLocation.lat, userLocation.lng)
            : new google.maps.LatLng(33.0891264, -83.2372736);
          console.log('Using fallback location for hazard:', fallbackLocation.toString());
          addAlert('Hazard', '', fallbackLocation).then(() => {
            console.log('Hazard alert posted with fallback location');
          }).catch(err => {
            console.error('Failed to post hazard alert with fallback:', err);
            showToastMessage('Failed to post hazard alert with fallback.', 7000);
          });
        },
        { maximumAge: 10000, timeout: 30000, enableHighAccuracy: true }
      );
    } else {
      console.error('Geolocation unavailable');
      showToastMessage('Geolocation not supported. Using default location for hazard.', 7000);
      const defaultLocation = new google.maps.LatLng(33.0891264, -83.2372736);
      console.log('Using default location for hazard:', defaultLocation.toString());
      addAlert('Hazard', '', defaultLocation).then(() => {
        console.log('Hazard alert posted with default location');
      }).catch(err => {
        console.error('Failed to post hazard alert with default:', err);
        showToastMessage('Failed to post hazard alert with default.', 7000);
      });
    }
  }

function enableMapClick() {
  isSelectingLocation = true;
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
}

function reverseGeocode(lat, lng) {
  return new Promise((resolve, reject) => {
    if (!window.google || !google.maps) {
      reject(new Error('Google Maps API not loaded'));
      return;
    }
    const geocoder = new google.maps.Geocoder();
    geocoder.geocode({ location: { lat, lng } }, (results, status) => {
      if (status === 'OK' && results[0]) {
        resolve(results[0].formatted_address);
      } else {
        reject(new Error(`Reverse geocode failed: ${status}`));
      }
    });
  });
}

function postSelectedAlert() {
  const alertType = document.getElementById('alertType');
  const alertNotes = document.getElementById('alertNotes');
  const selectedLocation = document.getElementById('selected-location');
  if (!alertType || !alertNotes || !selectedLocation) {
    console.error('Missing elements for posting alert:', { alertType: !!alertType, alertNotes: !!alertNotes, selectedLocation: !!selectedLocation });
    showToastMessage('Error: Required elements not found.', 7000);
    return;
  }
  const type = alertType.value;
  const notes = alertNotes.value.trim();
  const [lat, lng] = selectedLocation.textContent.split(', ').map(Number);
  addAlert(type, notes, new google.maps.LatLng(lat, lng)).then(() => {
    const detailedAlertBox = document.getElementById('detailedAlertBox');
    if (detailedAlertBox) {
      detailedAlertBox.classList.remove('active');
      detailedAlertBox.style.display = 'none';
    }
  });
}

function closeDetailedAlertBox() {
  const detailedAlertBox = document.getElementById('detailedAlertBox');
  if (detailedAlertBox) {
    detailedAlertBox.classList.remove('active');
    detailedAlertBox.style.display = 'none';
    if (isSelectingLocation) {
      google.maps.event.clearListeners(map, 'click');
      isSelectingLocation = false;
    }
    if (toastMessage) toastMessage.style.display = 'none';
    if (locationDisplay) locationDisplay.style.display = 'none';
    if (alertType) alertType.style.display = 'block';
    const alertTypeLabel = document.querySelector('#detailedAlertBox label[for="alertType"]');
    if (alertTypeLabel) alertTypeLabel.style.display = 'block';
    if (clickLocationBtn) clickLocationBtn.style.display = 'block';
    if (alertCurrentBtn) alertCurrentBtn.style.display = 'block';
    if (postAlertBtn) postAlertBtn.style.display = 'none';
    if (cancelAlertBtn) cancelAlertBtn.style.display = 'none';
    if (alertNotes) alertNotes.value = '';
  }
}

// Drag functionality for detailedAlertBox
function makeDraggable(element) {
  let isDragging = false;
  let currentX;
  let currentY;
  let initialX;
  let initialY;
  let xOffset = 0;
  let yOffset = 0;
  if (!element.style.left || !element.style.top) {
    element.style.left = '50%';
    element.style.top = '50%';
    console.log('Initialized detailedAlertBox position to center');
  }
  const h3 = element.querySelector('h3');
  if (h3) {
    h3.addEventListener('mousedown', (e) => {
      if (e.target !== h3) return;
      initialX = e.clientX - xOffset;
      initialY = e.clientY - yOffset;
      isDragging = true;
      element.classList.add('dragging');
      console.log('Started dragging detailedAlertBox');
    });
  }
  document.addEventListener('mousemove', (e) => {
    if (isDragging) {
      e.preventDefault();
      currentX = e.clientX - initialX;
      currentY = e.clientY - initialY;
      xOffset = currentX;
      yOffset = currentY;
      const rect = element.getBoundingClientRect();
      const maxX = window.innerWidth - rect.width;
      const maxY = window.innerHeight - rect.height;
      currentX = Math.max(0, Math.min(currentX, maxX));
      currentY = Math.max(0, Math.min(currentY, maxY));
      element.style.left = currentX + 'px';
      element.style.top = currentY + 'px';
    }
  });
  document.addEventListener('mouseup', () => {
    isDragging = false;
    element.classList.remove('dragging');
    console.log('Stopped dragging detailedAlertBox at:', { left: element.style.left || '50%', top: element.style.top || '50%' });
  });
  // Touch events
  h3.addEventListener('touchstart', (e) => {
    if (e.target !== h3) return;
    const touch = e.touches[0];
    initialX = touch.clientX - xOffset;
    initialY = touch.clientY - yOffset;
    isDragging = true;
    element.classList.add('dragging');
    console.log('Started touch dragging detailedAlertBox');
  }, { passive: false });
  document.addEventListener('touchmove', (e) => {
    if (isDragging) {
      e.preventDefault();
      const touch = e.touches[0];
      currentX = touch.clientX - initialX;
      currentY = touch.clientY - initialY;
      xOffset = currentX;
      yOffset = currentY;
      const rect = element.getBoundingClientRect();
      const maxX = window.innerWidth - rect.width;
      const maxY = window.innerHeight - rect.height;
      currentX = Math.max(0, Math.min(currentX, maxX));
      currentY = Math.max(0, Math.min(currentY, maxY));
      element.style.left = currentX + 'px';
      element.style.top = currentY + 'px';
    }
  }, { passive: false });
  document.addEventListener('touchend', () => {
    isDragging = false;
    element.classList.remove('dragging');
    console.log('Stopped touch dragging detailedAlertBox at:', { left: element.style.left || '50%', top: element.style.top || '50%' });
  }, { passive: false });
}

// Login/Logout Handling
if (loginBtn && loginUsername && loginPassword) {
  loginBtn.removeEventListener('click', () => {});
  loginBtn.addEventListener('click', () => {
    const username = loginUsername.value ? loginUsername.value.trim() : '';
    const password = loginPassword.value ? loginPassword.value.trim() : '';
    console.log('Login button clicked, input values:', { username, password: '[provided]' });
    if (username && password) {
      console.log('Attempting login with:', { username, password: '[provided]' });
      login(username, password, loginBtn, loginUsername, loginPassword);
    } else {
      console.error('Login attempt with missing username or password:', { username, password });
      showToastMessage('Username or email and password are required.', 5000);
    }
  });
  loginUsername.addEventListener('input', () => {
    console.log('Username input changed:', loginUsername.value);
  });
  loginPassword.addEventListener('input', () => {
    console.log('Password input changed: [provided]');
  });
} else {
  console.error('Login elements missing:', { loginBtn: !!loginBtn, loginUsername: !!loginUsername, loginPassword: !!loginPassword });
  setTimeout(() => {
    const retryLoginBtn = document.getElementById('login-btn');
    const retryLoginUsername = document.getElementById('login-username');
    const retryLoginPassword = document.getElementById('login-password');
    if (retryLoginBtn && retryLoginUsername && retryLoginPassword) {
      retryLoginBtn.removeEventListener('click', () => {});
      retryLoginBtn.addEventListener('click', () => {
        const username = retryLoginUsername.value ? retryLoginUsername.value.trim() : '';
        const password = retryLoginPassword.value ? retryLoginPassword.value.trim() : '';
        console.log('Retry login button clicked, input values:', { username, password: '[provided]' });
        if (username && password) {
          console.log('Attempting retry login with:', { username, password: '[provided]' });
          login(username, password, retryLoginBtn, retryLoginUsername, retryLoginPassword);
        } else {
          console.error('Retry login attempt with missing username or password:', { username, password });
          showToastMessage('Username or email and password are required.', 5000);
        }
      });
    } else {
      console.error('Retry login elements still missing:', { loginBtn: !!retryLoginBtn, loginUsername: !!retryLoginUsername, loginPassword: !!retryLoginPassword });
    }
  }, 1000);
}

if (profileBtn) {
  profileBtn.addEventListener('click', () => {
    console.log('Profile button clicked, currentUser:', currentUser);
    if (currentUser) {
      if (profileHud) {
        if (detailedAlertBox) {
          detailedAlertBox.classList.remove('active');
          detailedAlertBox.style.display = 'none';
          console.log('Closed detailedAlertBox on profile button click');
        }
        profileHud.classList.add('active');
        profileHud.style.display = 'flex';
        fetchUserProfile();
        currentTab = 'edit';
        if (tabButtons && tabButtons.length > 0) {
          tabButtons.forEach(button => button.classList.remove('active'));
          const editButton = document.querySelector('.tab-button[data-tab="edit"]');
          if (editButton) editButton.classList.add('active');
          if (accountInfo) accountInfo.classList.remove('active');
          if (editProfile) editProfile.classList.add('active');
          if (alertsTab) alertsTab.classList.remove('active');
          console.log('Edit profile tab activated');
        } else {
          console.error('Tab buttons not found');
        }
      } else {
        console.error('profileHud element not found');
      }
    } else {
      console.warn('No current user, profile action skipped');
      showToastMessage('Please log in to view profile.', 5000);
      logout();
    }
  });
}

if (closeBtn) {
  closeBtn.addEventListener('click', () => {
    if (profileHud) {
      profileHud.classList.remove('active');
      profileHud.style.display = 'none';
      const loginScreen = document.getElementById('login-screen');
      if (loginScreen) loginScreen.style.display = 'none';
    }
  });
}

if (saveProfileBtn) {
  saveProfileBtn.addEventListener('click', () => {
    const name = document.getElementById('edit-name')?.value.trim();
    const username = document.getElementById('edit-username')?.value.trim();
    const email = document.getElementById('edit-email')?.value.trim();
    const age = parseInt(document.getElementById('edit-age')?.value.trim());
    const dob = document.getElementById('edit-dob')?.value.trim();
    const location = document.getElementById('edit-location')?.value.trim();
    console.log('Saving profile:', { name, username, email, age, dob, location });
    if (!name || !username || !email || !age || !dob || !location) {
      showToastMessage('All fields are required.', 5000);
      return;
    }
    if (!/^\d{2}\/\d{2}\/\d{4}$/.test(dob)) {
      showToastMessage('DOB must be in MM/DD/YYYY format.', 5000);
      return;
    }
    if (isNaN(age) || age < 13) {
      showToastMessage('Age must be 13 or older.', 5000);
      return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      showToastMessage('Invalid email format.', 5000);
      return;
    }
    if (!/^[a-z0-9_]{3,20}$/.test(username)) {
      showToastMessage('Username must be 3-20 characters, letters, numbers, or underscores.', 5000);
      return;
    }
    // Check 3-month username change limit
    if (username !== currentUser.username && userProfile.lastUsernameChange) {
      const threeMonthsAgo = new Date();
      threeMonthsAgo.setMonth(threeMonthsAgo.getMonth() - 3);
      if (new Date(userProfile.lastUsernameChange) > threeMonthsAgo) {
        showToastMessage('You can only change your username once every 3 months.', 5000);
        return;
      }
    }
    // Check username availability
    if (username !== currentUser.username) {
      checkUsernameAvailability(username)
        .then(available => {
          if (!available) {
            showToastMessage('Username already taken.', 5000);
            return;
          }
          // Proceed with profile update
          fetchWithTokenRefresh(`${BASE_URL}/api/auth/update`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, username, email, age, dob, location })
          })
            .then(response => {
              if (!response.ok) return response.json().then(data => { throw new Error(data.msg || 'Update failed') });
              return response.json();
            })
            .then(data => {
              userProfile = data;
              currentUser = { ...currentUser, username: data.username, id: data._id };
              console.log('Profile updated:', userProfile);
              showToastMessage('Profile updated successfully!', 5000);
              updateProfileDisplay();
            })
            .catch(err => {
              console.error('Profile update error:', err.message);
              showToastMessage(`Failed to update profile: ${err.message}`, 7000);
              if (err.message.includes('User not found') || err.message.includes('Invalid token')) {
                logout();
              }
            });
        })
        .catch(err => {
          console.error('Username availability check error:', err.message);
          showToastMessage(err.message, 5000);
        });
    } else {
      // No username change, proceed with update
      fetchWithTokenRefresh(`${BASE_URL}/api/auth/update`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, username, email, age, dob, location })
      })
        .then(response => {
          if (!response.ok) return response.json().then(data => { throw new Error(data.msg || 'Update failed') });
          return response.json();
        })
        .then(data => {
          userProfile = data;
          currentUser = { ...currentUser, username: data.username, id: data._id };
          console.log('Profile updated:', userProfile);
          showToastMessage('Profile updated successfully!', 5000);
          updateProfileDisplay();
        })
        .catch(err => {
          console.error('Profile update error:', err.message);
          showToastMessage(`Failed to update profile: ${err.message}`, 7000);
          if (err.message.includes('User not found') || err.message.includes('Invalid token')) {
            logout();
          }
        });
    }
  });
}

if (tabButtons && tabButtons.length > 0) {
  tabButtons.forEach(button => {
    button.addEventListener('click', () => {
      tabButtons.forEach(btn => btn.classList.remove('active'));
      button.classList.add('active');
      currentTab = button.getAttribute('data-tab');
      if (accountInfo) accountInfo.classList.remove('active');
      if (editProfile) editProfile.classList.remove('active');
      if (alertsTab) alertsTab.classList.remove('active');
      let activeTab;
      if (currentTab === 'account') activeTab = accountInfo;
      else if (currentTab === 'edit') activeTab = editProfile;
      else if (currentTab === 'alerts') activeTab = alertsTab;
      if (activeTab) activeTab.classList.add('active');
      else console.error(`Tab content for ${currentTab} not found`);
      if (currentTab === 'alerts') {
        fetchAlerts();
      } else if (currentTab === 'account') {
        updateProfileDisplay();
        const loginScreen = document.getElementById('login-screen');
        if (loginScreen) loginScreen.style.display = 'none';
      }
      if (detailedAlertBox) {
        detailedAlertBox.classList.remove('active');
        detailedAlertBox.style.display = 'none';
        console.log('Closed detailedAlertBox on tab switch');
      }
    });
  });
} else {
  console.error('Tab buttons not initialized');
}

if (detailedAlertBtn) {
  detailedAlertBtn.addEventListener('click', () => {
    console.log('Detailed Alert button clicked');
    if (profileHud) {
      profileHud.classList.remove('active');
      profileHud.style.display = 'none';
      console.log('Closed profileHud on detailed alert button click');
    }
    showDetailedAlertBox();
  });
}

if (settingsBtn) {
  settingsBtn.addEventListener('click', () => {
    if (currentUser) {
      if (settingsHud) {
        settingsHud.classList.add('active');
        settingsHud.style.display = 'flex';
      } else console.error('settingsHud element not found');
    } else {
      showToastMessage('Please log in to access settings.', 5000);
      logout();
    }
  });
}

if (closeSettings) {
  closeSettings.addEventListener('click', () => {
    if (settingsHud) {
      settingsHud.classList.remove('active');
      settingsHud.style.display = 'none';
    } else console.error('closeSettings element not found');
  });
}

if (navAddress) {
  navAddress.addEventListener('click', showOverlay);
  navAddress.addEventListener('touchstart', showOverlay);
}

if (micButton) micButton.addEventListener('click', startVoiceRecognition);

if (navAddress) {
  navAddress.addEventListener('input', () => {
    console.time('Autocomplete process');
    console.log('Input detected:', navAddress.value);
    const query = navAddress.value;
    if (query.length > 2 && userLocation) {
      autocompleteService.getPlacePredictions(
        { input: query, location: new google.maps.LatLng(userLocation.lat, userLocation.lng), radius: 50000 },
        (predictions, status) => {
          console.log('Autocomplete status:', status);
          if (status === google.maps.places.PlacesServiceStatus.OK && predictions) {
            if (suggestions) suggestions.innerHTML = '';
            predictions.forEach(prediction => {
              const item = document.createElement('div');
              item.className = 'suggestion-item';
              item.textContent = prediction.description;
              item.addEventListener('click', () => {
                if (navAddress) navAddress.value = prediction.description;
                if (isNavigating) stopNavigation();
                startNavigation(prediction.description);
                if (navOverlay) navOverlay.style.display = 'none';
              });
              if (suggestions) suggestions.appendChild(item);
            });
          } else {
            if (suggestions) suggestions.innerHTML = '';
            console.log('No predictions or error:', status);
          }
          console.timeEnd('Autocomplete process');
        }
      );
    } else {
      if (suggestions) suggestions.innerHTML = '';
    }
  });
}

if (closeOverlay) closeOverlay.addEventListener('click', () => {
  if (navOverlay) navOverlay.style.display = 'none';
});

if (closeVoiceOverlay) closeVoiceOverlay.addEventListener('click', () => {
  stopVoiceRecognition();
  if (voiceOverlay) voiceOverlay.style.display = 'none';
  if (voiceInstruction) voiceInstruction.textContent = 'Speak the address or location...';
});

if (closeDetailedAlertBtn) closeDetailedAlertBtn.addEventListener('click', closeDetailedAlertBox);

if (clickLocationBtn) clickLocationBtn.addEventListener('click', enableMapClick);

if (alertCurrentBtn) {
  alertCurrentBtn.removeEventListener('click', alertAtCurrentLocation);
  alertCurrentBtn.addEventListener('click', alertAtCurrentLocation);
  console.log('alert-current-location button listener updated');
}

if (postAlertBtn) postAlertBtn.addEventListener('click', postSelectedAlert);

if (cancelAlertBtn) cancelAlertBtn.addEventListener('click', closeDetailedAlertBox);

if (hazardBtn) {
  hazardBtn.removeEventListener('click', addHazardMarker);
  hazardBtn.addEventListener('click', addHazardMarker);
  console.log('hazard-btn listener updated');
}

if (cancelBtn) cancelBtn.addEventListener('click', stopNavigation);

if (recenterBtn) recenterBtn.addEventListener('click', recenterMap);

if (muteBtn) {
  muteBtn.addEventListener('click', () => {
    isMuted = !isMuted;
    muteBtn.classList.toggle('muted');
    console.log('Mute toggled:', isMuted);
  });
}

if (rerouteYes) rerouteYes.addEventListener('click', () => {
  rerouteAroundHazards(currentHazards);
});

if (rerouteNo) rerouteNo.addEventListener('click', () => {
  ignoreHazards(currentHazards);
});

// Initialize drag functionality for detailedAlertBox
if (detailedAlertBox) {
  makeDraggable(detailedAlertBox);
  console.log('Drag functionality initialized for detailedAlertBox');
}

// Filter events
if (document.getElementById('alert-type-filter')) {
  document.getElementById('alert-type-filter').addEventListener('change', () => {
    currentPage = 1;
    updateAlertTable();
  });
}
if (document.getElementById('alert-user-filter')) {
  document.getElementById('alert-user-filter').addEventListener('change', () => {
    currentPage = 1;
    updateAlertTable();
  });
}

// Sync with real-time updates
function initializeSocket() {
  if (socket) {
    socket.on('hazard', (data) => {
      if (map && !alertMarkers.has(data._id)) {
        addMarkerFromDB(data);
        fetchAlerts();
      }
    });
    socket.on('detailedAlert', (data) => {
      if (map && !alertMarkers.has(data._id)) {
        addMarkerFromDB(data);
        fetchAlerts();
      }
    });
    socket.on('alert', (data) => {
      if (map) {
        new google.maps.Marker({
          position: { lat: data.location.coordinates[1], lng: data.location.coordinates[0] },
          map: map,
          title: data.type
        });
      }
    });
    socket.on('alertRemoved', (data) => {
      if (alertMarkers.has(data._id)) {
        alertMarkers.get(data._id).setMap(null);
        alertMarkers.delete(data._id);
        hazardMarkers = hazardMarkers.filter(h => h._id !== data._id);
        allAlerts = allAlerts.filter(a => a._id !== data._id);
        updateAlertTable();
      }
      console.log('Alert removed via socket:', data._id);
    });
    socket.on('locationUpdate', (data) => {
      if (map) {
        new google.maps.Marker({
          position: { lat: data.latitude, lng: data.longitude },
          map: map,
          title: 'User Location'
        });
      }
    });
  }
}

// Force Profile HUD width on load and resize
window.addEventListener('load', () => {
  const profileHud = document.getElementById('profile-hud');
  if (profileHud) {
    profileHud.style.width = '100%';
    profileHud.style.maxWidth = '650px';
    console.log('Forced Profile HUD width to 100% and max-width to 650px');
  }
});
window.addEventListener('resize', () => {
  const profileHud = document.getElementById('profile-hud');
  if (profileHud) {
    profileHud.style.width = '100%';
    profileHud.style.maxWidth = '650px';
    console.log('Resized Profile HUD to 100% and max-width to 650px');
  }
});

// Periodic cleanup of expired markers
setInterval(cleanExpiredMarkers, 60000); // Run every minute
});