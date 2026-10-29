// Scroll position survives the 5s auto-refresh, so a long device table does not jump to the top.
const scrollKey = `scroll:${location.pathname}`

window.addEventListener('DOMContentLoaded', () => {
  const saved = sessionStorage.getItem(scrollKey)
  if (saved !== null) {
    sessionStorage.removeItem(scrollKey)
    window.scrollTo(0, Number(saved))
  }
  if (document.querySelector('[data-refresh="true"]')) {
    setTimeout(() => {
      sessionStorage.setItem(scrollKey, String(window.scrollY))
      location.reload()
    }, 5000)
  }
})

document.addEventListener('submit', (event) => {
  const message = event.target.dataset.confirm
  if (message && !confirm(message)) event.preventDefault()
})
