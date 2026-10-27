// Two conveniences for forms. Neither is a check: the server still verifies everything, and the
// forms work with JavaScript turned off. Text is set with textContent only.
// A disabled button is not sent with the form: do not give a submit button a name or value.

document.addEventListener("submit", (event) => {
  // A file over the limit is not sent at all, so the user sees the message at once.
  const input = event.target.querySelector("input[type=file][data-max-bytes]");
  const file = input && input.files[0];
  if (file && file.size > Number(input.dataset.maxBytes)) {
    event.preventDefault();
    const box = document.getElementById("upload-error");
    box.textContent = "This file is too large. The limit is " + input.dataset.maxLabel + ".";
    box.hidden = false;
    return;
  }

  // Disable the submit button, so a hurried double click cannot send the form twice.
  const button = event.target.querySelector("button[type=submit]");
  if (!button) return;
  button.dataset.label = button.textContent;
  button.disabled = true;
  button.textContent = "Working…";
});

// After the Back button the browser may show the page with the button still disabled.
window.addEventListener("pageshow", () => {
  for (const button of document.querySelectorAll("button[data-label]")) {
    button.disabled = false;
    button.textContent = button.dataset.label;
    delete button.dataset.label;
  }
});
