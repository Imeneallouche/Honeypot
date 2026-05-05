import axios, { type AxiosError } from "axios";
import toast from "react-hot-toast";

import { useAuthStore } from "../store/authStore";

export const apiClient = axios.create({
  baseURL: "/api",
});

apiClient.interceptors.request.use((config) => {
  const token = useAuthStore.getState().accessToken;
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

apiClient.interceptors.response.use(
  (r) => r,
  (error: AxiosError) => {
    const status = error.response?.status;
    if (status === 401) {
      useAuthStore.getState().clear();
      toast.error("Session expired — sign in again.");
      if (typeof window !== "undefined" && !window.location.pathname.startsWith("/login")) {
        window.location.replace("/login");
      }
    }
    return Promise.reject(error);
  }
);
