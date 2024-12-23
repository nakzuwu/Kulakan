function openChatbot() {
  document.getElementById("chatbotWindow").style.display = "flex";
}

// Tutup jendela chatbot
function closeChatbot() {
  document.getElementById("chatbotWindow").style.display = "none";
}

// Kirim pesan dari chatbot
function sendMessage() {
  const input = document.getElementById("chatbotInput");
  const messages = document.getElementById("chatbotMessages");

  if (input.value.trim() !== "") {
    // Tambahkan pesan pengguna
    const userMessage = document.createElement("div");
    userMessage.classList.add("message", "user");
    userMessage.textContent = input.value;
    messages.appendChild(userMessage);

    // Simpan pesan pengguna
    const userInput = input.value;
    input.value = "";

    // Kirim pesan ke server
    fetch("/query", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ message: userInput }),
    })
      .then((response) => response.json())
      .then((data) => {
        // Tambahkan pesan chatbot ke jendela
        const botMessage = document.createElement("div");
        botMessage.classList.add("message", "bot");
        botMessage.textContent = data.response; // Respons dari server
        messages.appendChild(botMessage);

        // Scroll ke bawah
        messages.scrollTop = messages.scrollHeight;
      })
      .catch((error) => {
        console.error("Error:", error);

        // Tampilkan pesan error
        const errorMessage = document.createElement("div");
        errorMessage.classList.add("message", "bot");
        errorMessage.textContent = "Terjadi kesalahan. Silakan coba lagi.";
        messages.appendChild(errorMessage);

        // Scroll ke bawah
        messages.scrollTop = messages.scrollHeight;
      });
  }
}
