<template>
  <div>
    <h1>Google OAuth Login</h1>
    <button @click="login" class="login">Login with Google</button>
  </div>
</template>

<script>
import { ref } from "vue";
import axios from "axios";
export default {
  name: "Home",
  setup() {
    const error = ref(null);
    const authURL = ref(null);
    const login = async () => {
      try {
        window.location.href = "http://localhost:3000";
      } catch (error) {
        console.error("Error fetching URL:", error);
        error.value = "Failed to fetch URL. Please try again.";
      }
    };
    return { login };
  },
};
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style>
body {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 90vh;
}
.login {
  padding: 20px 20px;
  font-size: x-large;
  border-radius: 0.5rem;
  border: none;
  background-color: aquamarine;
  cursor: pointer;
  box-shadow: 0 25px 50px -12px rgb(0 0 0 / 0.25);
}
.login:hover {
  background-color: rgb(98, 199, 165);
}
</style>
