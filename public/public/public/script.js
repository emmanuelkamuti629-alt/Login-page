document.getElementById('registerForm').addEventListener('submit', async (e) => {
  e.preventDefault();

  // Get form values
  const firstName = document.getElementById('firstName').value.trim();
  const lastName = document.getElementById('lastName').value.trim();
  const email = document.getElementById('email').value.trim();
  const phone = document.getElementById('phone').value.trim();
  const password = document.getElementById('password').value;
  const confirmPassword = document.getElementById('confirmPassword').value;

  // Basic Validation
  if (password !== confirmPassword) {
    alert("Passwords do not match!");
    return;
  }

  if (!document.getElementById('terms').checked) {
    alert("You must agree to the Terms & Conditions.");
    return;
  }

  const formData = {
    firstName,
    lastName,
    email,
    phone,
    password
  };

  try {
    const response = await fetch('/api/register', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(formData)
    });

    const data = await response.json();

    if (response.ok) {
      alert('Account created successfully!');
      // Redirect to a dashboard or login page
      window.location.href = '/dashboard.html'; 
    } else {
      alert(`Error: ${data.message}`);
    }
  } catch (error) {
    console.error('Error:', error);
    alert('An error occurred. Please try again later.');
  }
});
