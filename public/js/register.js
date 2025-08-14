document.addEventListener('DOMContentLoaded', () => {
  console.log('register.js loaded, version 1.0.32');

  // DOM elements
  const fullNameInput = document.getElementById('name');
  const usernameInput = document.getElementById('username');
  const emailInput = document.getElementById('email');
  const passwordInput = document.getElementById('password');
  const confirmPasswordInput = document.getElementById('confirm-password');
  const ageInput = document.getElementById('age');
  const dobInput = document.getElementById('dob');
  const locationInput = document.getElementById('location');
  const registerBtn = document.getElementById('register-btn');
  const clearBtn = document.getElementById('clear-btn');
  const returnBtn = document.getElementById('return-btn');
  const errorMessages = {
    fullName: document.getElementById('name-error'),
    username: document.getElementById('username-error'),
    email: document.getElementById('email-error'),
    password: document.getElementById('password-error'),
    confirmPassword: document.getElementById('confirm-password-error'),
    age: document.getElementById('age-error'),
    dob: document.getElementById('dob-error'),
    location: document.getElementById('location-error')
  };

  // Validation and error handling
  function showError(field, message) {
    if (errorMessages[field]) {
      errorMessages[field].textContent = message;
      errorMessages[field].style.display = 'block';
      document.getElementById(field === 'fullName' ? 'name' : field).classList.add('invalid');
      document.getElementById(field === 'fullName' ? 'name' : field).classList.remove('valid');
    }
  }

  function clearError(field) {
    if (errorMessages[field]) {
      errorMessages[field].textContent = '';
      errorMessages[field].style.display = 'none';
      document.getElementById(field === 'fullName' ? 'name' : field).classList.remove('invalid');
      document.getElementById(field === 'fullName' ? 'name' : field).classList.add('valid');
    }
  }

  async function checkAvailability(username, email) {
    try {
      console.log('Checking availability:', { username, email });
      const response = await fetch('http://127.0.0.1:3000/api/auth/check-availability', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, email })
      });
      const data = await response.json();
      console.log('Availability check response:', data);
      if (!response.ok) {
        if (data.errors) {
          if (data.errors.username) showError('username', data.errors.username);
          if (data.errors.email) showError('email', data.errors.email);
        } else {
          showError('username', 'Error checking availability');
          showError('email', 'Error checking availability');
        }
        return false;
      }
      clearError('username');
      clearError('email');
      return data.available;
    } catch (err) {
      console.error('Availability check error:', err.message);
      showError('username', 'Server error, please try again');
      showError('email', 'Server error, please try again');
      return false;
    }
  }

  async function validateField(field, value) {
    switch (field) {
      case 'username':
        const trimmedUsername = value.trim().toLowerCase();
        if (!/^[a-z0-9_]{3,20}$/.test(trimmedUsername)) {
          showError('username', 'Username must be 3-20 characters, letters, numbers, or underscores');
          return false;
        }
        const usernameAvailable = await checkAvailability(trimmedUsername, emailInput.value.trim().toLowerCase());
        if (!usernameAvailable) return false;
        return true;
      case 'email':
        const trimmedEmail = value.trim().toLowerCase();
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmedEmail)) {
          showError('email', 'Invalid email format');
          return false;
        }
        const emailAvailable = await checkAvailability(usernameInput.value.trim().toLowerCase(), trimmedEmail);
        if (!emailAvailable) return false;
        return true;
      case 'password':
        if (!value || value.length < 8) {
          showError('password', 'Password must be at least 8 characters');
          return false;
        }
        console.log('Password validated, length:', value.length, 'value:', value);
        clearError('password');
        validateField('confirm-password', confirmPasswordInput.value);
        return true;
      case 'confirm-password':
        if (!value || value !== passwordInput.value) {
          showError('confirm-password', 'Passwords do not match');
          return false;
        }
        if (value.length < 8) {
          showError('confirm-password', 'Password must be at least 8 characters');
          return false;
        }
        console.log('Confirm password validated, length:', value.length, 'value:', value);
        clearError('confirm-password');
        return true;
      case 'fullName':
        clearError('fullName');
        return true;
      case 'age':
        const ageNum = parseInt(value);
        if (value && (isNaN(ageNum) || ageNum < 13)) {
          showError('age', 'Age must be 13 or older');
          return false;
        }
        clearError('age');
        return true;
      case 'dob':
        if (value && !/^\d{2}\/\d{2}\/\d{4}$/.test(value)) {
          showError('dob', 'DOB must be in MM/DD/YYYY format');
          return false;
        }
        if (value) {
          const [month, day, year] = value.split('/').map(Number);
          const date = new Date(year, month - 1, day);
          if (date.getFullYear() !== year || date.getMonth() !== month - 1 || date.getDate() !== day) {
            showError('dob', 'Invalid date');
            return false;
          }
        }
        clearError('dob');
        return true;
      case 'location':
        clearError('location');
        return true;
      default:
        return true;
    }
  }

  // Input event listeners for real-time validation
  fullNameInput.addEventListener('input', () => {
    console.log('Full Name input:', fullNameInput.value);
    validateField('fullName', fullNameInput.value);
  });
  usernameInput.addEventListener('input', () => {
    console.log('Username input:', usernameInput.value);
    validateField('username', usernameInput.value);
  });
  emailInput.addEventListener('input', () => {
    console.log('Email input:', emailInput.value);
    validateField('email', emailInput.value);
  });
  passwordInput.addEventListener('input', () => {
    console.log('Password input, length:', passwordInput.value.length, 'value:', passwordInput.value);
    validateField('password', passwordInput.value);
    validateField('confirm-password', confirmPasswordInput.value);
  });
  confirmPasswordInput.addEventListener('input', () => {
    console.log('Confirm password input, length:', confirmPasswordInput.value.length, 'value:', confirmPasswordInput.value);
    validateField('confirm-password', confirmPasswordInput.value);
  });
  ageInput.addEventListener('input', () => {
    console.log('Age input:', ageInput.value);
    validateField('age', ageInput.value);
  });
  dobInput.addEventListener('input', () => {
    console.log('DOB input:', dobInput.value);
    validateField('dob', dobInput.value);
  });
  locationInput.addEventListener('input', () => {
    console.log('Location input:', locationInput.value);
    validateField('location', locationInput.value);
  });

  // Register button
  registerBtn.addEventListener('click', async () => {
    console.log('Register button clicked');
    const fullName = fullNameInput.value.trim();
    const username = usernameInput.value.trim().toLowerCase();
    const email = emailInput.value.trim().toLowerCase();
    const password = passwordInput.value;
    const confirmPassword = confirmPasswordInput.value;
    const age = ageInput.value.trim();
    const dob = dobInput.value.trim();
    const location = locationInput.value.trim();

    console.log('Registration data:', {
      fullName,
      username,
      email,
      passwordLength: password.length,
      passwordValue: password,
      confirmPasswordLength: confirmPassword.length,
      confirmPasswordValue: confirmPassword,
      age,
      dob,
      location
    });

    // Validate all fields
    const validations = await Promise.all([
      validateField('fullName', fullName),
      validateField('username', username),
      validateField('email', email),
      validateField('password', password),
      validateField('confirm-password', confirmPassword),
      validateField('age', age),
      validateField('dob', dob),
      validateField('location', location)
    ]);

    if (!validations.every(valid => valid)) {
      console.log('Registration validation failed:', validations);
      alert('Please fix all errors before registering');
      return;
    }

    console.log('Submitting registration:', { username, email, passwordLength: password.length, name: fullName, age, dob, location });
    fetch('http://127.0.0.1:3000/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, email, name: fullName, age, dob, location })
    })
      .then(response => {
        console.log('Register response status:', response.status);
        if (!response.ok) return response.json().then(data => { throw new Error(data.msg || 'Registration failed', { cause: data }) });
        return response.json();
      })
      .then(data => {
        console.log('Registration successful:', data);
        localStorage.setItem('token', data.token);
        localStorage.setItem('refreshToken', data.refreshToken);
        alert('Registration successful! Redirecting to login...');
        setTimeout(() => window.location.href = '/', 2000);
      })
      .catch(err => {
        console.error('Registration error:', err.message, err.cause);
        if (err.cause?.errors) {
          if (err.cause.errors.username) showError('username', err.cause.errors.username);
          if (err.cause.errors.email) showError('email', err.cause.errors.email);
        } else {
          alert(`Registration failed: ${err.message}`);
        }
      });
  });

  // Clear button
  clearBtn.addEventListener('click', () => {
    console.log('Clear button clicked');
    fullNameInput.value = '';
    usernameInput.value = '';
    emailInput.value = '';
    passwordInput.value = '';
    confirmPasswordInput.value = '';
    ageInput.value = '';
    dobInput.value = '';
    locationInput.value = '';
    Object.keys(errorMessages).forEach(field => clearError(field));
  });

  // Return to login
  returnBtn.addEventListener('click', () => {
    console.log('Return to login clicked');
    window.location.href = '/';
  });
});