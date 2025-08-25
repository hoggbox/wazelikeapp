const VERSION = '1.0.60'; // Updated for Google Maps-like navigation, route line, and HUD fixes
// Global variables
let map;
let routePolyline;
let passedPolyline;
let currentDestination = null;
let liveLocationMarker = null;
let isNavigating = false;
let isFollowing = true; // Start with aggressive following
let isManualInteraction = false;
let previousPosition = null;
let routePath = [];
let recentDestinations = ['1827 Holly Hill Rd, Milledgeville, GA 31061', 'Walmart Milledgeville GA'];
let autocompleteService;
let placesService;
let directionsService;
let directionsRenderer;
let userLocation = { lat: 33.0891264, lng: -83.2372736 };
let socket = null;
let recognition = null;
let isMuted = false;
let hazardMarkers = [];
let lastLocationUpdate = 0;
let lastRerouteTime = 0;
let isSelectingLocation = false;
let alertMarkers = new Map();
let alertQueue = [];
let lastHazardTime = 0;
let currentUser = null;
let userProfile = { name: '', username: '', email: '', age: '', dob: null, location: '', _id: null, lastUsernameChange: null };
let allAlerts = [];
let ignoredHazards = [];
let currentHazards = [];
let directionsResponse = null;
const GOOGLE_MAPS_API_KEY = 'AIzaSyBSW8iQAE1AjjouEu4df-Cvq1ceUMLBit4';
const ALERTS_PER_PAGE = 5;
let currentPage = 1;
let currentTab = 'account';
let accountInfo, editProfile, alertsTab, tabButtons;
let femaleVoice = null;
let mapReadyResolve;
const mapReady = new Promise((resolve) => mapReadyResolve = resolve);
let lastInstruction = '';
let lastNavIndex = -1;
let lastDistanceToNext = Infinity;
let lastHeading = 0;
let geolocationWatchId = null;
let geolocationRetryCount = 0;
const MAX_GEOLOCATION_RETRIES = 3;
const REROUTE_COOLDOWN = 5000; // 5s cooldown for off-route rerouting
const UPDATE_THROTTLE = 60; // 60ms throttle for map updates
// Determine API and Socket.IO base URL
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
function showToastMessage(message, duration = 5000, isError = false) {
  const toastMessage = document.getElementById('toast-message');
  if (toastMessage) {
    toastMessage.textContent = message;
    toastMessage.classList.toggle('error', isError);
    toastMessage.style.display = 'block';
    toastMessage.style.opacity = '1';
    setTimeout(() => {
      toastMessage.style.opacity = '0';
      setTimeout(() => {
        toastMessage.style.display = 'none';
      }, 200);
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
      showToastMessage('Failed to geocode address.', 7000, true);
      return null;
    });
}
function provideVoiceNavigation(coords) {
  const navInstruction = document.getElementById('nav-instruction');
  const navDistance = document.getElementById('nav-distance');
  const instructionContainer = document.getElementById('instruction-container');
  if (!navInstruction || !navDistance) {
    console.error('HUD elements not found:', { navInstruction, navDistance, instructionContainer });
    showToastMessage('HUD elements missing. Please reload the page.', 7000, true);
    return;
  }
  if (routePath.length > 1 && coords && directionsResponse) {
    const currentPos = new google.maps.LatLng(coords.latitude, coords.longitude);
    const closest = findClosestPointOnRoute(currentPos, routePath);
    const nextIndex = Math.min(closest.index + 1, routePath.length - 1);
    let stepDistance = closest.distance; // Default to closest point distance
    console.log('Navigation check:', { distance: closest.distance, nextIndex, heading: coords.heading });
    // Check if user is near the destination (within 50 meters)
    if (currentDestination) {
      const destPos = new google.maps.LatLng(currentDestination[0], currentDestination[1]);
      const distanceToDest = google.maps.geometry.spherical.computeDistanceBetween(currentPos, destPos);
      if (distanceToDest < 50) {
        console.log('Destination reached, stopping navigation');
        stopNavigation();
        if (!isMuted && 'speechSynthesis' in window && femaleVoice) {
          const utterance = new SpeechSynthesisUtterance('You have reached your destination.');
          utterance.voice = femaleVoice;
          utterance.lang = 'en-US';
          utterance.volume = 1.0;
          window.speechSynthesis.speak(utterance);
        }
        showToastMessage('Destination reached!', 5000);
        return;
      }
    }
    // Find the corresponding step in directionsResponse
    let currentStep = null;
    let stepIndex = 0;
    for (const leg of directionsResponse.routes[0].legs) {
      for (let i = 0; i < leg.steps.length; i++) {
        const step = leg.steps[i];
        const stepPath = google.maps.geometry.encoding.decodePath(step.polyline.points);
        const stepStart = stepPath[0];
        const stepEnd = stepPath[stepPath.length - 1];
        const distToStart = google.maps.geometry.spherical.computeDistanceBetween(currentPos, stepStart);
        const distToEnd = google.maps.geometry.spherical.computeDistanceBetween(currentPos, stepEnd);
        if (distToStart < 50 || distToEnd < 50 || stepPath.some(point => google.maps.geometry.spherical.computeDistanceBetween(currentPos, point) < 50)) {
          currentStep = step;
          stepIndex = i;
          stepDistance = step.distance.value; // Use step distance if available
          break;
        }
      }
      if (currentStep) break;
    }
    let instruction = 'Continue straight';
    let turnDirection = null;
    if (currentStep && currentStep.maneuver && currentStep.maneuver.includes('turn')) {
      const nextStep = directionsResponse.routes[0].legs[0].steps[stepIndex + 1];
      const streetName = currentStep.end_address || currentStep.instructions.replace(/<[^>]+>/g, '').split(' onto ')[1]?.split(' toward ')[0] || 'unknown street';
      const towardStreet = nextStep ? nextStep.end_address || nextStep.instructions.replace(/<[^>]+>/g, '').split(' onto ')[1]?.split(' toward ')[0] || 'your destination' : 'your destination';
      turnDirection = currentStep.maneuver.includes('left') ? 'left' : 'right';
      instruction = `Turn ${turnDirection} onto ${streetName} toward ${towardStreet}`;
    } else if (currentStep) {
      instruction = `Continue on ${currentStep.end_address || currentStep.instructions.replace(/<[^>]+>/g, '').split(' onto ')[1]?.split(' toward ')[0] || 'current road'}`;
    }
    if (instruction !== lastInstruction || closest.index > lastNavIndex) {
      if (!isMuted && 'speechSynthesis' in window && femaleVoice) {
        const utterance = new SpeechSynthesisUtterance(instruction);
        utterance.voice = femaleVoice;
        utterance.lang = 'en-US';
        utterance.volume = 1.0;
        utterance.rate = 1.0;
        window.speechSynthesis.speak(utterance);
        console.log('Voice navigation:', instruction, 'with:', femaleVoice.name);
        showToastMessage(`Navigation: ${instruction}`, 5000);
      } else if (!femaleVoice) {
        console.warn('No female voice available, skipping navigation instruction');
      }
      lastInstruction = instruction;
      navInstruction.textContent = instruction;
      navDistance.textContent = `${Math.round(stepDistance)} m`;
      if (instructionContainer) {
        const leftArrow = instructionContainer.querySelector('.fa-arrow-left');
        const rightArrow = instructionContainer.querySelector('.fa-arrow-right');
        if (leftArrow && rightArrow) {
          leftArrow.classList.remove('active');
          rightArrow.classList.remove('active');
          if (turnDirection === 'left') {
            leftArrow.classList.add('active');
          } else if (turnDirection === 'right') {
            rightArrow.classList.add('active');
          }
        } else {
          console.warn('Turn arrows not found in instructionContainer');
        }
      }
    }
    lastNavIndex = closest.index;
    lastDistanceToNext = stepDistance;
  } else if (isNavigating && routePath.length > 0) {
    console.warn('Missing coords or route data for voice navigation:', { coords, routePathLength: routePath.length });
    navInstruction.textContent = 'Waiting for navigation data...';
    navDistance.textContent = 'N/A';
    if (instructionContainer) {
      const leftArrow = instructionContainer.querySelector('.fa-arrow-left');
      const rightArrow = instructionContainer.querySelector('.fa-arrow-right');
      if (leftArrow && rightArrow) {
        leftArrow.classList.remove('active');
        rightArrow.classList.remove('active');
      }
    }
  } else {
    navInstruction.textContent = 'No navigation active';
    navDistance.textContent = 'N/A';
    if (instructionContainer) {
      const leftArrow = instructionContainer.querySelector('.fa-arrow-left');
      const rightArrow = instructionContainer.querySelector('.fa-arrow-right');
      if (leftArrow && rightArrow) {
        leftArrow.classList.remove('active');
        rightArrow.classList.remove('active');
      }
    }
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
      showToastMessage('Hazard detected on route.', 5000);
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
    showToastMessage('No active navigation to reroute.', 5000, true);
    return;
  }
  console.log('Rerouting around hazards:', hazards);
  updateRoute([userLocation.lat, userLocation.lng], currentDestination, true);
  const reroutePrompt = document.getElementById('reroutePrompt');
  if (reroutePrompt) {
    reroutePrompt.style.display = 'none';
    console.log('Reroute prompt hidden after rerouting');
  }
  ignoredHazards.push(...hazards.map(h => h._id));
  showToastMessage('Rerouted around hazards.', 5000);
}
function ignoreHazards(hazards) {
  hazards.forEach(h => ignoredHazards.push(h._id));
  const reroutePrompt = document.getElementById('reroutePrompt');
  if (reroutePrompt) {
    reroutePrompt.style.display = 'none';
    console.log('Ignoring hazards:', hazards);
  }
  showToastMessage('Hazards ignored.', 5000);
}
async function updateRoute(start, end, avoidHazards = false) {
  await mapReady;
  let retries = 0;
  const maxRetries = 3;
  async function tryUpdateRoute() {
    try {
      console.time('Route calculation');
      console.log(`Fetching route from [${start}] to [${end}] with avoidHazards: ${avoidHazards}, attempt ${retries + 1}`);
      const request = {
        origin: new google.maps.LatLng(start[0], start[1]),
        destination: new google.maps.LatLng(end[0], end[1]),
        travelMode: google.maps.TravelMode.DRIVING,
        provideRouteAlternatives: avoidHazards,
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
      directionsResponse = response;
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
      if (passedPolyline) passedPolyline.setMap(null);
      passedPolyline = new google.maps.Polyline({
        path: [],
        strokeColor: '#ff4444',
        strokeOpacity: 0.4,
        strokeWeight: 4,
        map: map
      });
      const timeMs = selectedRoute.legs.reduce((acc, leg) => acc + leg.duration.value * 1000, 0);
      const distanceM = selectedRoute.legs.reduce((acc, leg) => acc + leg.distance.value, 0);
      if (eta) eta.textContent = `${Math.round(timeMs / 60000)} min`;
      if (dta) dta.textContent = `${Math.round(distanceM / 1609.34)} mi`;
      const navEta = document.getElementById('nav-eta');
      if (navEta) navEta.textContent = `${Math.round(timeMs / 60000)} min`;
      console.timeEnd('Route calculation');
      showToastMessage(avoidHazards ? 'Route updated to avoid hazards.' : 'Route updated.', 5000);
      // Trigger initial navigation instruction
      provideVoiceNavigation({ latitude: start[0], longitude: start[1], heading: lastHeading });
    } catch (err) {
      console.error('Route calculation failed:', err);
      retries++;
      if (retries < maxRetries) {
        console.log(`Retrying route calculation (attempt ${retries + 1})...`);
        setTimeout(tryUpdateRoute, 2000 * retries);
      } else {
        console.error('Max retries reached for route calculation');
        showToastMessage('Failed to calculate route after retries.', 7000, true);
        stopNavigation();
      }
    }
  }
  tryUpdateRoute();
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
      showToastMessage('No user logged in, alert queued offline.', 7000, true);
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
        if (data.msg === 'Error: Cannot post duplicate alert or alert in same exact location, please try a different location') {
          console.log('Duplicate alert not saved:', data.alert._id);
          marker.setMap(null);
          showToastMessage(data.msg, 7000, true);
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
        showToastMessage(`${type} alert posted successfully.`, 5000);
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
          showToastMessage('Failed to save alert to server, queued offline.', 7000, true);
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
    showToastMessage('Please log in to view alerts.', 5000, true);
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
      showToastMessage('Alerts fetched successfully.', 5000);
    })
    .catch(err => {
      console.error('Failed to fetch alerts:', err.message);
      showToastMessage(`Failed to fetch alerts: ${err.message}`, 7000, true);
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
      showToastMessage(`Username check failed: ${err.message}`, 7000, true);
      throw err;
    });
}
function fetchUserProfile() {
  if (!currentUser) {
    console.warn('No current user, skipping profile fetch');
    showToastMessage('Please log in to view profile.', 5000, true);
    logout();
    return;
  }
  const token = localStorage.getItem('token');
  if (!token) {
    console.warn('No token available, skipping user profile fetch');
    showToastMessage('Please log in to view profile.', 5000, true);
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
      showToastMessage('Profile fetched successfully.', 5000);
    })
    .catch(err => {
      console.error('Failed to fetch user profile:', err.message);
      showToastMessage(`Failed to fetch profile: ${err.message}`, 7000, true);
      if (err.message.includes('User not found') || err.message.includes('Invalid token')) {
        logout();
      }
    });
}
function updateProfileDisplay() {
  if (!accountInfo) {
    console.error('accountInfo element not found in DOM');
    showToastMessage('Profile display not found.', 7000, true);
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
  const existingLogoutButton = accountInfo.querySelector('.logout-btn');
  if (existingLogoutButton) {
    existingLogoutButton.remove();
  }
  const logoutButton = document.createElement('button');
  logoutButton.textContent = 'Logout';
  logoutButton.className = 'logout-btn';
  logoutButton.style.cssText = `
    padding: 8px 15px;
    background: #ff4444;
    border: none;
    border-radius: 5px;
    color: #ffffff;
    cursor: pointer;
    font-family: 'Roboto', sans-serif;
    margin-top: 10px;
    touch-action: manipulation;
    -webkit-tap-highlight-color: transparent;
  `;
  logoutButton.addEventListener('click', () => {
    logout();
  });
  logoutButton.addEventListener('touchend', (e) => {
    e.preventDefault();
    logout();
  }, { passive: false });
  accountInfo.appendChild(logoutButton);
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
    showToastMessage('Alert table not found.', 7000, true);
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
      <td>${new Date(alert.createdAt).toLocaleString()}</td>
      <td>${userDisplay}</td>
      <td class="action-cell">
        ${canDelete ? `<button class="delete-btn" data-id="${alert._id}"><i class="fas fa-times"></i></button>` : ''}
        <button class="info-btn" data-id="${alert._id}"><i class="fas fa-info-circle"></i></button>
      </td>
    `;
    const detailsRow = document.createElement('tr');
    detailsRow.className = 'details-row';
    detailsRow.dataset.id = alert._id;
    detailsRow.innerHTML = `
      <td colspan="5" class="details-content">
        <p><span>User:</span> ${userDisplay}</p>
        <p><span>Timestamp:</span> ${new Date(alert.createdAt).toLocaleString()}</p>
        <p><span>Location:</span> ${alert.locationStr}</p>
        <p><span>Notes:</span> ${alert.notes || 'None'}</p>
        <button class="collapse-btn"><i class="fas fa-caret-up"></i></button>
      </td>
    `;
    table.appendChild(row);
    table.appendChild(detailsRow);
    const deleteBtn = row.querySelector('.delete-btn');
    const infoBtn = row.querySelector('.info-btn');
    const collapseBtn = detailsRow.querySelector('.collapse-btn');
    if (deleteBtn) {
      deleteBtn.addEventListener('click', () => {
        window.removeAlert(alert._id);
      });
      deleteBtn.addEventListener('touchend', (e) => {
        e.preventDefault();
        window.removeAlert(alert._id);
      }, { passive: false });
    }
    infoBtn.addEventListener('click', () => {
      const isActive = detailsRow.classList.contains('active');
      document.querySelectorAll('.details-row').forEach(row => row.classList.remove('active'));
      if (!isActive) {
        detailsRow.classList.add('active');
        showToastMessage('Alert details expanded.', 5000);
      }
    });
    infoBtn.addEventListener('touchend', (e) => {
      e.preventDefault();
      infoBtn.click();
    }, { passive: false });
    collapseBtn.addEventListener('click', () => {
      detailsRow.classList.remove('active');
      showToastMessage('Alert details collapsed.', 5000);
    });
    collapseBtn.addEventListener('touchend', (e) => {
      e.preventDefault();
      collapseBtn.click();
    }, { passive: false });
  });
  updatePagination(filteredAlerts.length);
}
function updatePagination(totalAlerts) {
  const pagination = document.getElementById('alert-pagination');
  if (!pagination) {
    console.error('Pagination element not found in DOM');
    showToastMessage('Pagination not found.', 7000, true);
    return;
  }
  pagination.innerHTML = '';
  const totalPages = Math.ceil(totalAlerts / ALERTS_PER_PAGE);
  const prevButton = document.createElement('button');
  prevButton.textContent = '<';
  prevButton.disabled = currentPage === 1;
  prevButton.addEventListener('click', () => {
    if (currentPage > 1) {
      currentPage--;
      updateAlertTable();
      showToastMessage(`Switched to page ${currentPage}.`, 5000);
    }
  });
  prevButton.addEventListener('touchend', (e) => {
    e.preventDefault();
    if (currentPage > 1) {
      currentPage--;
      updateAlertTable();
      showToastMessage(`Switched to page ${currentPage}.`, 5000);
    }
  }, { passive: false });
  pagination.appendChild(prevButton);
  for (let i = 1; i <= totalPages; i++) {
    const button = document.createElement('button');
    button.textContent = i;
    button.className = i === currentPage ? 'active' : '';
    button.addEventListener('click', () => {
      currentPage = i;
      updateAlertTable();
      showToastMessage(`Switched to page ${i}.`, 5000);
    });
    button.addEventListener('touchend', (e) => {
      e.preventDefault();
      currentPage = i;
      updateAlertTable();
      showToastMessage(`Switched to page ${i}.`, 5000);
    }, { passive: false });
    pagination.appendChild(button);
  }
  const nextButton = document.createElement('button');
  nextButton.textContent = '>';
  nextButton.disabled = currentPage === totalPages;
  nextButton.addEventListener('click', () => {
    if (currentPage < totalPages) {
      currentPage++;
      updateAlertTable();
      showToastMessage(`Switched to page ${currentPage}.`, 5000);
    }
  });
  nextButton.addEventListener('touchend', (e) => {
    e.preventDefault();
    if (currentPage < totalPages) {
      currentPage++;
      updateAlertTable();
      showToastMessage(`Switched to page ${currentPage}.`, 5000);
    }
  }, { passive: false });
  pagination.appendChild(nextButton);
}
function populateUserFilter() {
  const userFilter = document.getElementById('alert-user-filter');
  if (!userFilter) {
    console.error('User filter element not found in DOM');
    showToastMessage('User filter not found.', 7000, true);
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
  userFilter.addEventListener('change', () => {
    showToastMessage(`Filtered alerts by user: ${userFilter.value || 'All Users'}.`, 5000);
  });
}
function fetchWithTokenRefresh(url, options = {}) {
  const token = localStorage.getItem('token');
  if (!token) {
    console.error('No token available');
    showToastMessage('No token available, please log in.', 5000, true);
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
        showToastMessage('Session expired, please log in again.', 5000, true);
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
    showToastMessage('No refresh token, please log in again.', 5000, true);
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
    .then(data => {
      showToastMessage('Session refreshed successfully.', 5000);
      return data.token || null;
    })
    .catch(err => {
      console.error('Token refresh failed:', err);
      showToastMessage('Failed to refresh session, please log in again.', 5000, true);
      logout();
      return Promise.resolve(null);
    });
}
function login(username, password, loginBtn, loginUsername, loginPassword) {
  if (!username || !password) {
    console.error('Login attempt with missing username or password:', { username, password });
    showToastMessage('Username or email and password are required.', 5000, true);
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
      showToastMessage('Logged in successfully.', 5000);
    })
    .catch(err => {
      console.error('Login error:', err.message);
      showToastMessage(`Login failed: ${err.message}`, 7000, true);
    });
}
function logout() {
  try {
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
    const navInput = document.getElementById('nav-input');
    const navHud = document.getElementById('nav-hud');
    if (loginScreen) loginScreen.style.display = 'flex';
    if (map) map.style.display = 'none';
    if (profileHud && profileHud.classList) profileHud.classList.remove('active');
    if (settingsHud && settingsHud.classList) settingsHud.classList.remove('active');
    if (profileHud) profileHud.style.display = 'none';
    if (navInput) {
      navInput.classList.remove('hidden');
      navInput.style.opacity = '1';
      navInput.style.transform = 'translateX(-50%)';
    }
    if (navHud) {
      navHud.classList.remove('active');
      navHud.style.display = 'none';
    }
    console.log('Logged out, resetting to login screen');
    showToastMessage('Logged out successfully.', 5000);
    window.location.href = '/';
  } catch (err) {
    console.error('Logout error:', err);
    showToastMessage('Failed to log out.', 7000, true);
  }
}
function alertAtCurrentLocation() {
  const alertType = document.getElementById('alertType');
  if (!alertType) {
    console.error('alertType element not found');
    showToastMessage('Error: Alert type not found.', 7000, true);
    return;
  }
  const type = alertType.value;
  if (!currentUser) {
    console.warn('No current user, cannot post alert');
    showToastMessage('Please log in to post alerts.', 5000, true);
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
          showToastMessage('Alert posted at current location.', 5000);
        }).catch(err => {
          console.error('Failed to post alert at current location:', err);
          showToastMessage(err.message || 'Failed to post alert at current location.', 7000, true);
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
        showToastMessage(errorMessage, 7000, true);
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
          showToastMessage('Alert posted with fallback location.', 5000);
        }).catch(err => {
          console.error('Failed to post alert with fallback:', err);
          showToastMessage(err.message || 'Failed to post alert with fallback.', 7000, true);
        });
      },
      { maximumAge: 10000, timeout: 30000, enableHighAccuracy: true }
    );
  } else {
    console.error('Geolocation unavailable');
    showToastMessage('Geolocation not supported. Using default location.', 7000, true);
    const defaultLocation = new google.maps.LatLng(33.0891264, -83.2372736);
    console.log('Using default location for alert:', defaultLocation.toString());
    addAlert('Hazard', '', defaultLocation).then(() => {
      const detailedAlertBox = document.getElementById('detailedAlertBox');
      if (detailedAlertBox) {
        detailedAlertBox.classList.remove('active');
        detailedAlertBox.style.display = 'none';
      }
      console.log('Alert posted with default location');
      showToastMessage('Alert posted with default location.', 5000);
    }).catch(err => {
      console.error('Failed to post alert with default:', err);
      showToastMessage(err.message || 'Failed to post alert with default.', 7000, true);
    });
  }
}
function initializeMapAfterLogin() {
  const mapElement = document.getElementById('map');
  const navInput = document.getElementById('nav-input');
  if (mapElement) mapElement.style.display = 'block';
  if (navInput) {
    navInput.classList.remove('hidden');
    navInput.style.opacity = '1';
    navInput.style.transform = 'translateX(-50%)';
  }
  if (window.google && google.maps) {
    window.initMap();
  } else {
    const script = document.createElement('script');
    script.src = `https://maps.googleapis.com/maps/api/js?key=${GOOGLE_MAPS_API_KEY}&libraries=places,geometry&callback=initMap&v=${VERSION}`;
    script.async = true;
    script.defer = true;
    document.head.appendChild(script);
    script.onload = () => window.initMap();
    script.onerror = () => {
      console.error('Google Maps API failed to load');
      showToastMessage('Failed to load map.', 7000, true);
    };
  }
}
window.removeAlert = function(alertId) {
  const token = localStorage.getItem('token');
  if (!token) {
    console.error('No token available, cannot remove alert');
    showToastMessage('Please log in to remove alerts.', 7000, true);
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
      showToastMessage(`Failed to remove alert: ${err.message}`, 7000, true);
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
  const navInput = document.getElementById('nav-input');
  const navHud = document.getElementById('nav-hud');
  if (!token) {
    if (loginScreen) loginScreen.style.display = 'flex';
    if (mapElement) mapElement.style.display = 'none';
    if (navInput) {
      navInput.classList.remove('hidden');
      navInput.style.opacity = '1';
      navInput.style.transform = 'translateX(-50%)';
    }
    if (navHud) {
      navHud.classList.remove('active');
      navHud.style.display = 'none';
    }
    showToastMessage('Please log in to access the map.', 5000, true);
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
    if (navInput) {
      navInput.classList.remove('hidden');
      navInput.style.opacity = '1';
      navInput.style.transform = 'translateX(-50%)';
    }
    if (navHud) {
      navHud.classList.remove('active');
      navHud.style.display = 'none';
    }
    fetchUserProfile();
    fetchAlerts();
  } catch (err) {
    console.error('Token validation error:', err);
    if (loginScreen) loginScreen.style.display = 'flex';
    if (mapElement) mapElement.style.display = 'none';
    localStorage.removeItem('token');
    localStorage.removeItem('refreshToken');
    showToastMessage('Invalid session, please log in again.', 5000, true);
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
    mapTypeControl: false,
    gestureHandling: 'greedy',
    tilt: 0
  });
  if (!map) {
    console.error('Map initialization failed');
    showToastMessage('Failed to initialize map.', 7000, true);
    return;
  }
  autocompleteService = new google.maps.places.AutocompleteService();
  placesService = new google.maps.places.PlacesService(map);
  directionsService = new google.maps.DirectionsService();
  directionsRenderer = new google.maps.DirectionsRenderer({ map: map, suppressMarkers: true });
  console.log('Map, Directions, and Places initialized');
  mapReadyResolve();
  map.addListener('dragstart', () => {
    if (isNavigating) {
      isManualInteraction = true;
      isFollowing = false;
      console.log('Manual drag detected, stopping auto-follow');
      showToastMessage('Manual map interaction detected. Use recenter to re-engage navigation follow.', 5000);
    }
  });
  map.addListener('zoom_changed', () => {
    if (isNavigating && !isManualInteraction) {
      isManualInteraction = true;
      isFollowing = false;
      console.log('Manual zoom detected, stopping auto-follow');
      showToastMessage('Manual zoom detected. Use recenter to re-engage navigation follow.', 5000);
    }
  });
  startGeolocationWatch();
  console.timeEnd('Map initialization');
};
function startGeolocationWatch() {
  if (navigator.geolocation) {
    if (geolocationWatchId) {
      navigator.geolocation.clearWatch(geolocationWatchId);
    }
    let lastUpdateTime = 0;
    geolocationWatchId = navigator.geolocation.watchPosition(
      (position) => {
        const now = Date.now();
        if (now - lastUpdateTime < UPDATE_THROTTLE) return;
        lastUpdateTime = now;
        geolocationRetryCount = 0;
        lastLocationUpdate = now;
        let currentPos = new google.maps.LatLng(position.coords.latitude, position.coords.longitude);
        userLocation = { lat: position.coords.latitude, lng: position.coords.longitude };
        console.log('WatchPosition updated user location:', userLocation, 'Time:', now);
        let heading = position.coords.heading;
        if (heading === null || heading === undefined) {
          if (previousPosition && routePath.length > 0) {
            const closest = findClosestPointOnRoute(currentPos, routePath);
            const nextIndex = Math.min(closest.index + 1, routePath.length - 1);
            heading = google.maps.geometry.spherical.computeHeading(currentPos, routePath[nextIndex]);
          } else {
            heading = lastHeading;
          }
        }
        lastHeading = heading || lastHeading;
        if (map) {
          if (liveLocationMarker) {
            liveLocationMarker.setPosition(currentPos);
            liveLocationMarker.setIcon({
              path: 'M -10,10 L 0,-10 L 10,10 Z',
              fillColor: '#00bcd4',
              fillOpacity: 1,
              strokeColor: '#000000',
              strokeWeight: 2,
              scale: 1.5,
              anchor: new google.maps.Point(0, 0),
              rotation: heading || 0
            });
          } else {
            liveLocationMarker = new google.maps.Marker({
              position: currentPos,
              map: map,
              icon: {
                path: 'M -10,10 L 0,-10 L 10,10 Z',
                fillColor: '#00bcd4',
                fillOpacity: 1,
                strokeColor: '#000000',
                strokeWeight: 2,
                scale: 1.5,
                anchor: new google.maps.Point(0, 0),
                rotation: heading || 0
              },
              title: 'Your Location',
              zIndex: 1001
            });
          }
          console.log('Triangle marker updated at:', currentPos.toString(), 'Heading:', heading || 0);
        }
        if (isNavigating && routePath.length > 0) {
          const closest = findClosestPointOnRoute(currentPos, routePath);
          if (closest.distance > 30 && (now - lastRerouteTime > REROUTE_COOLDOWN)) {
            console.log('User off-route, rerouting...', { distance: closest.distance });
            showToastMessage('Off-route detected, rerouting...', 5000);
            lastRerouteTime = now;
            updateRoute([position.coords.latitude, position.coords.longitude], currentDestination);
            return;
          }
          if (closest.distance < 30) {
            currentPos = routePath[closest.index];
            console.log('Snapped position to route at index:', closest.index);
          }
          const passedPath = routePath.slice(0, closest.index + 1);
          const futurePath = routePath.slice(closest.index);
          if (passedPolyline) {
            passedPolyline.setPath(passedPath);
          }
          if (routeWazeLikeApp) {
            routePolyline.setPath(futurePath);
          }
          if (isFollowing) {
            map.setCenter(currentPos);
            map.setZoom(18);
            map.setTilt(45);
            map.setHeading(heading || 0);
          }
          provideVoiceNavigation({ ...position.coords, heading });
        }
        previousPosition = { lat: position.coords.latitude, lng: position.coords.longitude };
        checkHazardsOnRoute();
      },
      (err) => {
        console.warn('WatchPosition error:', err);
        geolocationRetryCount++;
        const navInstruction = document.getElementById('nav-instruction');
        const navDistance = document.getElementById('nav-distance');
        const instructionContainer = document.getElementById('instruction-container');
        if (navInstruction) {
          navInstruction.textContent = 'Waiting for location...';
          if (instructionContainer) {
            const leftArrow = instructionContainer.querySelector('.fa-arrow-left');
            const rightArrow = instructionContainer.querySelector('.fa-arrow-right');
            if (leftArrow && rightArrow) {
              leftArrow.classList.remove('active');
              rightArrow.classList.remove('active');
            }
          }
        }
        if (navDistance) navDistance.textContent = 'N/A';
        if (geolocationRetryCount <= MAX_GEOLOCATION_RETRIES) {
          console.log(`Retrying geolocation watch (attempt ${geolocationRetryCount})...`);
          setTimeout(startGeolocationWatch, 5000);
        } else {
          showToastMessage('Geolocation failed after retries. Using last known location.', 7000, true);
          if (map && !liveLocationMarker) {
            liveLocationMarker = new google.maps.Marker({
              position: new google.maps.LatLng(userLocation.lat, userLocation.lng),
              map: map,
              icon: {
                path: 'M -10,10 L 0,-10 L 10,10 Z',
                fillColor: '#00bcd4',
                fillOpacity: 1,
                strokeColor: '#000000',
                strokeWeight: 2,
                scale: 1.5,
                anchor: new google.maps.Point(0, 0),
                rotation: lastHeading || 0
              },
              title: 'Your Location (Fallback)',
              zIndex: 1001
            });
            console.log('Fallback triangle marker set at:', userLocation);
          }
        }
      },
      { maximumAge: 0, timeout: 30000, enableHighAccuracy: true }
    );
    navigator.geolocation.getCurrentPosition(
      (position) => {
        userLocation = { lat: position.coords.latitude, lng: position.coords.longitude };
        lastLocationUpdate = Date.now();
        console.log('Initial user location:', userLocation);
        if (map) {
          map.setCenter(userLocation);
          if (!liveLocationMarker) {
            liveLocationMarker = new google.maps.Marker({
              position: new google.maps.LatLng(userLocation.lat, userLocation.lng),
              map: map,
              icon: {
                path: 'M -10,10 L 0,-10 L 10,10 Z',
                fillColor: '#00bcd4',
                fillOpacity: 1,
                strokeColor: '#000000',
                strokeWeight: 2,
                scale: 1.5,
                anchor: new google.maps.Point(0, 0),
                rotation: position.coords.heading || 0
              },
              title: 'Your Location',
              zIndex: 1001
            });
            console.log('Initial triangle marker set at:', userLocation);
          }
        }
        showToastMessage('Initial location acquired.', 5000);
      },
      (err) => {
        console.warn('Initial geolocation failed, using fallback:', err, userLocation);
        showToastMessage('Failed to get initial location, using fallback.', 7000, true);
        if (map && !liveLocationMarker) {
          liveLocationMarker = new google.maps.Marker({
            position: new google.maps.LatLng(userLocation.lat, userLocation.lng),
            map: map,
            icon: {
              path: 'M -10,10 L 0,-10 L 10,10 Z',
              fillColor: '#00bcd4',
              fillOpacity: 1,
              strokeColor: '#000000',
              strokeWeight: 2,
              scale: 1.5,
              anchor: new google.maps.Point(0, 0),
              rotation: 0
            },
            title: 'Your Location (Fallback)',
            zIndex: 1001
          });
          console.log('Fallback triangle marker set at:', userLocation);
        }
      },
      { maximumAge: 0, timeout: 30000, enableHighAccuracy: true }
    );
  } else {
    showToastMessage('Geolocation not supported.', 7000, true);
    const navInstruction = document.getElementById('nav-instruction');
    const navDistance = document.getElementById('nav-distance');
    const instructionContainer = document.getElementById('instruction-container');
    if (navInstruction) {
      navInstruction.textContent = 'Geolocation not supported';
      if (instructionContainer) {
        const leftArrow = instructionContainer.querySelector('.fa-arrow-left');
        const rightArrow = instructionContainer.querySelector('.fa-arrow-right');
        if (leftArrow && rightArrow) {
          leftArrow.classList.remove('active');
          rightArrow.classList.remove('active');
        }
      }
    }
    if (navDistance) navDistance.textContent = 'N/A';
    if (map && !liveLocationMarker) {
      liveLocationMarker = new google.maps.Marker({
        position: new google.maps.LatLng(userLocation.lat, userLocation.lng),
        map: map,
        icon: {
          path: 'M -10,10 L 0,-10 L 10,10 Z',
          fillColor: '#00bcd4',
          fillOpacity: 1,
          strokeColor: '#000000',
          strokeWeight: 2,
          scale: 1.5,
          anchor: new google.maps.Point(0, 0),
          rotation: 0
        },
        title: 'Your Location (Default)',
        zIndex: 1001
      });
      console.log('Default triangle marker set at:', userLocation);
    }
  }
}
function recenterMap() {
  if (navigator.geolocation && map && isNavigating) {
    navigator.geolocation.getCurrentPosition(
      (position) => {
        const { latitude, longitude } = position.coords;
        let currentPos = new google.maps.LatLng(latitude, longitude);
        let heading = position.coords.heading || lastHeading;
        if (routePath.length > 0) {
          const closest = findClosestPointOnRoute(currentPos, routePath);
          if (closest.distance < 30) {
            currentPos = routePath[closest.index];
          }
          const nextPointIndex = Math.min(closest.index + 1, routePath.length - 1);
          if (nextPointIndex < routePath.length) {
            const nextPoint = routePath[nextPointIndex];
            heading = google.maps.geometry.spherical.computeHeading(currentPos, nextPoint);
          }
        }
        map.setCenter(currentPos);
        map.setZoom(18);
        map.setTilt(45);
        map.setHeading(heading);
        isManualInteraction = false;
        isFollowing = true;
        console.log('Map recentered at:', currentPos.toString(), 'Heading:', heading);
        showToastMessage('Map recentered and locked to user.', 5000);
        provideVoiceNavigation({ latitude, longitude, heading });
      },
      (err) => {
        console.warn('Recenter geolocation error:', err);
        showToastMessage('Failed to recenter map. Using last known location.', 7000, true);
        let currentPos = new google.maps.LatLng(userLocation.lat, userLocation.lng);
        let heading = lastHeading;
        if (routePath.length > 0) {
          const closest = findClosestPointOnRoute(currentPos, routePath);
          if (closest.distance < 30) {
            currentPos = routePath[closest.index];
          }
          const nextPointIndex = Math.min(closest.index + 1, routePath.length - 1);
          if (nextPointIndex < routePath.length) {
            const nextPoint = routePath[nextPointIndex];
            heading = google.maps.geometry.spherical.computeHeading(currentPos, nextPoint);
          }
        }
        map.setCenter(currentPos);
        map.setZoom(18);
        map.setTilt(45);
        map.setHeading(heading);
        isManualInteraction = false;
        isFollowing = true;
        console.log('Map recentered with fallback at:', currentPos.toString(), 'Heading:', heading);
        showToastMessage('Map recentered with fallback location.', 5000);
        provideVoiceNavigation({ latitude: userLocation.lat, longitude: userLocation.lng, heading });
      },
      { maximumAge: 0, timeout: 30000, enableHighAccuracy: true }
    );
  } else {
    showToastMessage('Geolocation not supported for recentering.', 7000, true);
  }
}
function startVoiceRecognition() {
  if (!('webkitSpeechRecognition' in window)) {
    showToastMessage('Voice recognition not supported in this browser.', 7000, true);
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
    showToastMessage('Voice recognition started.', 5000);
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
      showToastMessage('No voice input detected.', 5000, true);
    }
  };
  recognition.onerror = (event) => {
    console.error('Voice recognition error:', event.error);
    if (voiceInstruction) voiceInstruction.textContent = `Error: ${event.error}. Please try again.`;
    showToastMessage(`Voice recognition error: ${event.error}`, 7000, true);
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
    showToastMessage('Voice recognition stopped.', 5000);
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
      showToastMessage('Waiting for voice confirmation.', 5000);
    };
    recognition.onresult = (event) => {
      const confirmation = event.results[0][0].transcript.toLowerCase().trim();
      console.log('Confirmation input:', confirmation);
      if (confirmation.includes('yes')) {
        startNavigation(transcript);
        showToastMessage(`Confirmed destination: ${transcript}`, 5000);
      } else if (confirmation.includes('no')) {
        if (voiceInstruction) voiceInstruction.textContent = 'Please try again...';
        const retryUtterance = new SpeechSynthesisUtterance('Please try again.');
        retryUtterance.voice = femaleVoice;
        window.speechSynthesis.speak(retryUtterance);
        showToastMessage('Voice input rejected, retrying.', 5000);
        setTimeout(() => startVoiceRecognition(), 1000);
      } else {
        if (voiceInstruction) voiceInstruction.textContent = 'Please say "yes" or "no"...';
        const promptUtterance = new SpeechSynthesisUtterance('Please say "yes" or "no".');
        promptUtterance.voice = femaleVoice;
        window.speechSynthesis.speak(promptUtterance);
        showToastMessage('Please say "yes" or "no".', 5000);
        setTimeout(() => confirmVoiceInput(transcript), 1000);
      }
      stopVoiceRecognition();
    };
    recognition.onerror = (event) => {
      console.error('Confirmation error:', event.error);
      if (voiceInstruction) voiceInstruction.textContent = `Error: ${event.error}. Please try again.`;
      showToastMessage(`Voice confirmation error: ${event.error}`, 7000, true);
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
    showToastMessage('Text-to-speech not supported or no voice available.', 7000, true);
    startNavigation(transcript);
  }
}
function showDetailedAlertBox() {
  console.time('Show detailed alert box');
  console.log('Showing detailed alert box, element:', detailedAlertBox);
  if (detailedAlertBox) {
    detailedAlertBox.classList.add('active');
    detailedAlertBox.style.display = 'flex';
    detailedAlertBox.style.left = '50%';
    detailedAlertBox.style.top = '50%';
    detailedAlertBox.style.transform = 'translate(-50%, -50%)';
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
    showToastMessage('Detailed alert box opened.', 5000);
  } else {
    console.error('detailedAlertBox element not found');
    showToastMessage('Error: Detailed alert box not found.', 7000, true);
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
      showToastMessage('Please log in to post alerts.', 5000, true);
      logout();
      reject(new Error('No authenticated user'));
      return;
    }
    addMarker(type, notes, position).then(() => {
      console.timeEnd(`Add ${type} alert`);
      resolve();
    }).catch(err => {
      console.error('Failed to post alert:', err);
      showToastMessage(err.message || 'Failed to post alert.', 7000, true);
      console.timeEnd(`Add ${type} alert`);
      reject(err);
    });
  });
}
function addHazardMarker() {
  const now = Date.now();
  if (now - lastHazardTime < 1000) {
    console.log('Hazard add debounced, too soon');
    showToastMessage('Please wait before posting another hazard.', 5000, true);
    return;
  }
  lastHazardTime = now;
  console.log('Hazard button clicked, checking geolocation...');
  if (!currentUser) {
    console.warn('No current user, cannot post hazard');
    showToastMessage('Please log in to post alerts.', 5000, true);
    logout();
    return;
  }
  if (navigator.geolocation) {
    console.log('Requesting geolocation for hazard alert');
    navigator.geolocation.getCurrentPosition(
      (position) => {
        const { latitude, longitude } = position.coords;
        userLocation = { lat: latitude, lng: longitude };
        lastLocationUpdate = now;
        console.log('Current location retrieved for hazard:', userLocation);
        addAlert('Hazard', '', new google.maps.LatLng(latitude, longitude)).then(() => {
          console.log('Hazard alert posted at:', userLocation);
          showToastMessage('Hazard alert posted successfully.', 5000);
        }).catch(err => {
          console.error('Failed to post hazard alert:', err);
          showToastMessage(err.message || 'Failed to post hazard alert.', 7000, true);
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
        showToastMessage(errorMessage, 7000, true);
        const fallbackLocation = userLocation.lat && userLocation.lng
          ? new google.maps.LatLng(userLocation.lat, userLocation.lng)
          : new google.maps.LatLng(33.0891264, -83.2372736);
        console.log('Using fallback location for hazard:', fallbackLocation.toString());
        addAlert('Hazard', '', fallbackLocation).then(() => {
          console.log('Hazard alert posted with fallback location');
          showToastMessage('Hazard alert posted with fallback location.', 5000);
        }).catch(err => {
          console.error('Failed to post hazard alert with fallback:', err);
          showToastMessage(err.message || 'Failed to post hazard alert with fallback.', 7000, true);
        });
      },
      { maximumAge: 10000, timeout: 30000, enableHighAccuracy: true }
    );
  } else {
    console.error('Geolocation unavailable');
    showToastMessage('Geolocation not supported. Using default location for hazard.', 7000, true);
    const defaultLocation = new google.maps.LatLng(33.0891264, -83.2372736);
    console.log('Using default location for hazard:', defaultLocation.toString());
    addAlert('Hazard', '', defaultLocation).then(() => {
      console.log('Hazard alert posted with default location');
      showToastMessage('Hazard alert posted with default location.', 5000);
    }).catch(err => {
      console.error('Failed to post hazard alert with default:', err);
      showToastMessage(err.message || 'Failed to post hazard alert with default.', 7000, true);
    });
  }
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
      showToastMessage('Location selected for alert.', 5000);
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
      showToastMessage('Failed to geocode selected location.', 7000, true);
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
        showToastMessage('Location selected for alert.', 5000);
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
        showToastMessage('Failed to geocode selected location.', 7000, true);
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
      showToastMessage('Google Maps API not loaded.', 7000, true);
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
      showToastMessage('Dragging alert box.', 5000);
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
    showToastMessage('Alert box drag stopped.', 5000);
    e.preventDefault();
  };
  document.addEventListener('mouseup', stopDrag);
  document.addEventListener('touchend', stopDrag, { passive: false });
}
window.addEventListener('DOMContentLoaded', () => {
  console.time('DOM initialization');
  console.log('DOM fully loaded at:', new Date().toLocaleTimeString());
  const hud = document.getElementById('hud');
  const controlHud = document.getElementById('control-hud');
  const speedLimit = document.getElementById('speedLimit');
  const eta = document.getElementById('eta');
  const dta = document.getElementById('dta');
  const time = document.getElementById('time');
  const navAddress = document.getElementById('navAddress');
  const navInput = document.getElementById('nav-input');
  const navHud = document.getElementById('nav-hud');
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
  if (navOverlay) {
    navOverlay.style.display = 'none';
    console.log('navOverlay set to hidden on load');
  }
  if (voiceOverlay) {
    voiceOverlay.style.display = 'none';
    console.log('voiceOverlay set to hidden on load');
  }
  if (detailedAlertBox) {
    detailedAlertBox.style.display = 'none';
    detailedAlertBox.style.left = '50%';
    detailedAlertBox.style.top = '50%';
    console.log('detailedAlertBox set to hidden on load, element:', detailedAlertBox);
  }
  if (profileHud) {
    profileHud.style.display = 'none';
    console.log('profileHud set to hidden on load');
  }
  if (settingsHud) {
    settingsHud.style.display = 'none';
    console.log('settingsHud set to hidden on load');
  }
  if (reroutePrompt) {
    reroutePrompt.style.display = 'none';
    console.log('reroutePrompt set to hidden on load');
  }
  if (navInput) {
    navInput.classList.remove('hidden');
    navInput.style.opacity = '1';
    navInput.style.transform = 'translateX(-50%)';
    console.log('navInput set to visible on load');
  }
  if (navHud) {
    navHud.classList.remove('active');
    navHud.style.display = 'none';
    console.log('navHud set to hidden on load');
  }
  if (settingsHud) {
    const existingSettingsLogout = settingsHud.querySelector('.logout-btn');
    if (!existingSettingsLogout) {
      const settingsLogoutButton = document.createElement('button');
      settingsLogoutButton.textContent = 'Logout';
      settingsLogoutButton.className = 'logout-btn';
      settingsLogoutButton.style.cssText = `
        padding: 8px 15px;
        background: #ff4444;
        border: none;
        border-radius: 5px;
        color: #ffffff;
        cursor: pointer;
        font-family: 'Roboto', sans-serif;
        margin-top: 10px;
        touch-action: manipulation;
        -webkit-tap-highlight-color: transparent;
      `;
      settingsLogoutButton.addEventListener('click', () => {
        logout();
      });
      settingsLogoutButton.addEventListener('touchend', (e) => {
        e.preventDefault();
        logout();
      }, { passive: false });
      settingsHud.appendChild(settingsLogoutButton);
    }
  }
  function loadSocketIOScript() {
    return new Promise((resolve, reject) => {
      if (window.io) {
        resolve();
        return;
      }
      const script = document.createElement('script');
      script.src = `${BASE_URL}/socket.io/socket.io.js`;
      script.async = true;
      let socketRetries = 0;
      const maxSocketRetries = 3;
      script.onload = () => {
        console.log('Socket.IO script loaded successfully');
        resolve();
      };
      script.onerror = () => {
        console.error('Failed to load Socket.IO script, attempt:', socketRetries + 1);
        socketRetries++;
        if (socketRetries < maxSocketRetries) {
          console.log(`Retrying Socket.IO load (attempt ${socketRetries + 1})...`);
          setTimeout(() => {
            document.head.appendChild(script.cloneNode());
          }, 2000 * socketRetries);
        } else {
          console.error('Max retries reached for Socket.IO load');
          showToastMessage('Failed to load Socket.IO.', 7000, true);
          reject(new Error('Socket.IO script failed to load'));
        }
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
          showToastMessage('Connected to server.', 5000);
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
              showToastMessage('Alert removed from map.', 5000);
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
          showToastMessage('Failed to connect to server.', 5000, true);
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
        const handleSelect = () => {
          if (navAddress) navAddress.value = dest;
          startNavigation(dest);
          if (navOverlay) navOverlay.style.display = 'none';
          showToastMessage(`Selected recent destination: ${dest}`, 5000);
        };
        item.addEventListener('click', handleSelect);
        item.addEventListener('touchend', handleSelect, { passive: false });
        recentLocations.appendChild(item);
      });
      showToastMessage('Navigation overlay opened.', 5000);
    } else {
      console.error('navOverlay not found');
      showToastMessage('Failed to open navigation overlay.', 5000, true);
    }
    console.timeEnd('Show overlay');
  }
  async function startNavigation(address) {
    console.time('Start navigation');
    await mapReady;
    isNavigating = true;
    isFollowing = true;
    isManualInteraction = false;
    console.log('Navigation started, setting isNavigating to true');
    if (hud) hud.classList.add('navigating');
    if (controlHud) controlHud.classList.add('navigating');
    if (navInput) {
      navInput.classList.add('hidden');
      navInput.style.opacity = '0';
      navInput.style.transform = 'translateX(-50%) translateY(-20px)';
    }
    if (navHud) {
      navHud.classList.add('active');
      navHud.style.display = 'flex';
      navHud.style.opacity = '1';
      navHud.style.transform = 'translateX(-50%)';
      const navInstruction = document.getElementById('nav-instruction');
      const navDistance = document.getElementById('nav-distance');
      const navEta = document.getElementById('nav-eta');
      const instructionContainer = document.getElementById('instruction-container');
      if (navInstruction) navInstruction.textContent = 'Starting navigation...';
      if (navDistance) navDistance.textContent = 'Calculating...';
      if (navEta) navEta.textContent = 'Calculating...';
      if (instructionContainer) {
        const leftArrow = instructionContainer.querySelector('.fa-arrow-left');
        const rightArrow = instructionContainer.querySelector('.fa-arrow-right');
        if (leftArrow && rightArrow) {
          leftArrow.classList.remove('active');
          rightArrow.classList.remove('active');
        }
      }
    }
    console.log('HUD classes updated:', { hudClass: hud?.className, controlHudClass: controlHud?.className, navInputHidden: navInput?.className, navHudActive: navHud?.className });
    routePath = [];
    ignoredHazards = [];
    directionsResponse = null;
    const destination = await geocodeWithGoogle(address);
    if (!destination) {
      console.error('Geocoding failed for address:', address);
      showToastMessage('Could not geocode address. Please check your input.', 7000, true);
      stopNavigation();
      return;
    }
    if (!recentDestinations.includes(address)) {
      recentDestinations.unshift(address);
      if (recentDestinations.length > 5) recentDestinations.pop();
    }
    currentDestination = destination;
    let retries = 0;
    const maxRetries = 3;
    async function tryStartNavigation() {
      if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(
          (position) => {
            const { latitude, longitude } = position.coords;
            userLocation = { lat: latitude, lng: longitude };
            lastLocationUpdate = Date.now();
            console.log('Current location for navigation start:', userLocation);
            map.setCenter(userLocation);
            map.setZoom(18);
            map.setTilt(45);
            map.setHeading(position.coords.heading || lastHeading);
            updateRoute([latitude, longitude], destination).then(() => {
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
              showToastMessage('Navigation started.', 5000);
              provideVoiceNavigation({ latitude, longitude, heading: position.coords.heading || lastHeading });
            }).catch(err => {
              console.error('Route update failed:', err);
              retries++;
              if (retries < maxRetries) {
                console.log(`Retrying navigation start (attempt ${retries + 1})...`);
                setTimeout(tryStartNavigation, 2000 * retries);
              } else {
                console.error('Max retries reached for navigation start');
                showToastMessage('Failed to start navigation after retries.', 7000, true);
                stopNavigation();
              }
            });
          },
          (err) => {
            console.error('Geolocation error for navigation start:', err);
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
            showToastMessage(errorMessage, 7000, true);
            retries++;
            if (retries < maxRetries) {
              console.log(`Retrying navigation start with fallback location (attempt ${retries + 1})...`);
              setTimeout(() => {
                updateRoute([userLocation.lat, userLocation.lng], destination).then(() => {
                  map.setCenter(userLocation);
                  map.setZoom(18);
                  map.setTilt(45);
                  map.setHeading(lastHeading);
                  checkHazardsOnRoute();
                  showToastMessage('Navigation started with fallback location.', 5000);
                  provideVoiceNavigation({ latitude: userLocation.lat, longitude: userLocation.lng, heading: lastHeading });
                }).catch(err => {
                  console.error('Route update with fallback failed:', err);
                  if (retries < maxRetries) {
                    console.log(`Retrying navigation start (attempt ${retries + 1})...`);
                    setTimeout(tryStartNavigation, 2000 * retries);
                  } else {
                    console.error('Max retries reached for navigation start with fallback');
                    showToastMessage('Failed to start navigation after retries.', 7000, true);
                    stopNavigation();
                  }
                });
              }, 2000 * retries);
            } else {
              console.error('Max retries reached for navigation start');
              showToastMessage('Failed to start navigation after retries.', 7000, true);
              stopNavigation();
            }
          },
          { maximumAge: 0, timeout: 30000, enableHighAccuracy: true }
        );
      } else {
        console.error('Geolocation unavailable, using fallback:', userLocation);
        updateRoute([userLocation.lat, userLocation.lng], destination).then(() => {
          map.setCenter(userLocation);
          map.setZoom(18);
          map.setTilt(45);
          map.setHeading(lastHeading);
          checkHazardsOnRoute();
          showToastMessage('Navigation started with fallback location.', 5000);
          provideVoiceNavigation({ latitude: userLocation.lat, longitude: userLocation.lng, heading: lastHeading });
        }).catch(err => {
          console.error('Route update with fallback failed:', err);
          retries++;
          if (retries < maxRetries) {
            console.log(`Retrying navigation start with fallback (attempt ${retries + 1})...`);
            setTimeout(tryStartNavigation, 2000 * retries);
          } else {
            console.error('Max retries reached for navigation start with fallback');
            showToastMessage('Failed to start navigation after retries.', 7000, true);
            stopNavigation();
          }
        });
      }
    }
    tryStartNavigation();
    console.timeEnd('Start navigation');
  }
  function stopNavigation() {
    console.log('Stopping navigation, attempting to clear route');
    isNavigating = false;
    isFollowing = false;
    routePath = [];
    currentDestination = null;
    ignoredHazards = [];
    lastInstruction = '';
    lastNavIndex = -1;
    lastDistanceToNext = Infinity;
    directionsResponse = null;
    if (hud) hud.classList.remove('navigating');
    if (controlHud) controlHud.classList.remove('navigating');
    if (navInput) {
      navInput.classList.remove('hidden');
      navInput.style.opacity = '0';
      navInput.style.transform = 'translateX(-50%)';
      setTimeout(() => {
        navInput.style.opacity = '1';
      }, 50);
    }
    if (navHud) {
      navHud.style.opacity = '0';
      setTimeout(() => {
        navHud.classList.remove('active');
        navHud.style.display = 'none';
        const instructionContainer = document.getElementById('instruction-container');
        if (instructionContainer) {
          const leftArrow = instructionContainer.querySelector('.fa-arrow-left');
          const rightArrow = instructionContainer.querySelector('.fa-arrow-right');
          if (leftArrow && rightArrow) {
            leftArrow.classList.remove('active');
            rightArrow.classList.remove('active');
          }
        }
      }, 300);
    }
    if (routePolyline) {
      routePolyline.setMap(null);
      routePolyline = null;
    }
    if (passedPolyline) {
      passedPolyline.setMap(null);
      passedPolyline = null;
    }
    if (directionsRenderer) {
      directionsRenderer.setMap(null);
    }
    if (eta) eta.textContent = 'N/A';
    if (dta) dta.textContent = 'N/A';
    if (time) time.textContent = '0:00';
    const navInstruction = document.getElementById('nav-instruction');
    const navDistance = document.getElementById('nav-distance');
    const navEta = document.getElementById('nav-eta');
    if (navInstruction) navInstruction.textContent = 'No navigation active';
    if (navDistance) navDistance.textContent = 'N/A';
    if (navEta) navEta.textContent = 'N/A';
    map.setZoom(13);
    map.setTilt(0);
    map.setHeading(0);
    showToastMessage('Navigation stopped.', 5000);
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
                showToastMessage(`Selected destination: ${prediction.description}`, 5000);
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
      showToastMessage('Profile opened.', 5000);
    };
    profileBtn.addEventListener('click', handleProfile);
    profileBtn.addEventListener('touchend', handleProfile, { passive: false });
  }
  if (closeBtn) {
    const handleCloseProfile = () => {
      profileHud.classList.remove('active');
      profileHud.style.display = 'none';
      showToastMessage('Profile closed.', 5000);
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
        showToastMessage(`Switched to ${currentTab} tab.`, 5000);
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
      if (!updates.username || !updates.email) {
        console.error('Username or email missing in profile update');
        showToastMessage('Username and email are required.', 7000, true);
        return;
      }
      const token = localStorage.getItem('token');
      if (!token) {
        console.error('No token available for profile update');
        showToastMessage('Please log in to update profile.', 5000, true);
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
          userProfile = { ...userProfile, ...data };
          currentUser = { ...currentUser, username: data.username, id: data._id };
          updateProfileDisplay();
          updateEditProfileForm();
          console.log('Profile updated:', userProfile);
          showToastMessage('Profile updated successfully.', 5000);
          profileHud.classList.remove('active');
          profileHud.style.display = 'none';
          accountInfo.classList.add('active');
        })
        .catch(err => {
          console.error('Profile update error:', err.message);
          showToastMessage(`Failed to update profile: ${err.message}`, 7000, true);
        });
    };
    saveProfileBtn.addEventListener('click', handleSaveProfile);
    saveProfileBtn.addEventListener('touchend', handleSaveProfile, { passive: false });
  }
  if (settingsBtn) {
    const handleSettings = () => {
      settingsHud.style.display = 'flex';
      settingsHud.classList.add('active');
      showToastMessage('Settings opened.', 5000);
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
  if (loginBtn && loginUsername && loginPassword) {
    const handleLogin = () => {
      login(loginUsername.value, loginPassword.value, loginBtn, loginUsername, loginPassword);
    };
    loginBtn.addEventListener('click', handleLogin);
    loginBtn.addEventListener('touchend', handleLogin, { passive: false });
  }
  if (rerouteYes) {
    const handleRerouteYes = () => rerouteAroundHazards(currentHazards);
    rerouteYes.addEventListener('click', handleRerouteYes);
    rerouteYes.addEventListener('touchend', handleRerouteYes, { passive: false });
  }
  if (rerouteNo) {
    const handleRerouteNo = () => ignoreHazards(currentHazards);
    rerouteNo.addEventListener('click', handleRerouteNo);
    rerouteNo.addEventListener('touchend', handleRerouteNo, { passive: false });
  }
  if (detailedAlertBox) {
    makeDraggable(detailedAlertBox);
  }
  if (addAlertBtn) {
    const handleAddAlert = () => showDetailedAlertBox();
    addAlertBtn.addEventListener('click', handleAddAlert);
    addAlertBtn.addEventListener('touchend', handleAddAlert, { passive: false });
  }
  document.addEventListener('touchstart', (e) => {
    if (e.touches.length > 1) {
      e.preventDefault();
    }
  }, { passive: false });
  document.addEventListener('touchmove', (e) => {
    if (e.touches.length > 1) {
      e.preventDefault();
    }
  }, { passive: false });
  document.addEventListener('contextmenu', (e) => {
    e.preventDefault();
    e.stopPropagation();
    return false;
  });
  console.timeEnd('DOM initialization');
});