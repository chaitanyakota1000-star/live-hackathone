// Dev 2: real dashboard logic goes here.
// For now this just confirms nginx -> backend proxying works.

fetch('/api/ping')
  .then((res) => res.json())
  .then((data) => {
    document.getElementById('status').textContent = data.pong
      ? 'Backend connected ✅'
      : 'Unexpected response from backend';
  })
  .catch(() => {
    document.getElementById('status').textContent = 'Could not reach backend ❌';
  });
