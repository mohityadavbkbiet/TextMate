// App.js - Frontend for the Text Utility Application

/**
 * Main React component for the TextUtils application.
 * This component provides the user interface for text input,
 * various text manipulation operations (uppercase, lowercase,
 * title case, reverse), and text analysis (word count, character count,
 * sentence count, read time). It interacts with a Node.js Express backend
 * for performing these operations and includes multi-language support.
 *
 * This updated version focuses on improving the visual layout,
 * spacing, typography, and overall user experience using Bootstrap 5
 * and custom CSS for a more polished look. It also integrates
 * with the backend's user authentication (signup/login) functionality,
 * allowing core text utility features to be used by both logged-in
 * and anonymous users. Operations performed by logged-in users will be
 * associated with their user ID in the backend.
 *
 * Technologies used: React.js, Vite, Bootstrap 5, Axios (for API calls), Animate.css for subtle animations.
 */

// --- Import React Hooks and Libraries ---
import React, { useState, useEffect, useRef, useCallback } from "react";
import axios from "axios"; // Used for making HTTP requests to the backend.

// --- Localization / Internationalization (i18n) Setup ---
// This object holds all the language translations.
const translations = {
  en: {
    appName: "TextMate - Your Text Utility",
    heroSubtitle: "Transform and analyze your text with ease.",
    placeholder: "Enter or paste your text here...",
    buttons: {
      uppercase: "UPPERCASE",
      lowercase: "lowercase",
      titlecase: "Title Case",
      reverse: "Reverse",
      copy: "Copy Text",
      clear: "Clear All",
      analyze: "Analyze",
      darkMode: "Dark Theme",
      lightMode: "Light Theme",
      language: "Language",
      login: "Login",
      logout: "Logout",
      signup: "Sign Up",
      close: "Close",
      confirm: "Confirm",
      submit: "Submit",
    },
    analysis: {
      summary: "Your Text Summary",
      words: "Words",
      characters: "Characters (No Spaces)",
      sentences: "Sentences",
      readTime: "Estimated Read Time",
      minutes: "min read",
    },
    messages: {
      copied: "Text copied to clipboard!",
      copyFailed: "Failed to copy text.",
      clearConfirm: "Are you sure you want to clear all text?",
      errorFetching: "Error performing operation:",
      loading: "Processing text...",
      noText: "Please enter some text to perform operations.",
      modalTitle: "Confirm Action",
      modalClearTextContent:
        "This action will clear all text from the input area and reset analysis. Do you want to proceed?",
      loginPrompt:
        "Log in or sign up to access features like operation history and to save your text transformations.",
      loginSuccess: "Logged in successfully!",
      loginFailed: "Login failed:",
      signupSuccess: "Signed up successfully! Please log in.",
      signupFailed: "Sign up failed:",
      logoutSuccess: "Logged out successfully!",
      usernameRequired: "Username is required.",
      passwordRequired: "Password is required.",
      passwordMismatch: "Passwords do not match.",
      sessionExpired: "Session expired or unauthorized. Please log in again.",
    },
    auth: {
      loginTitle: "Login to TextMate",
      signupTitle: "Sign Up for TextMate",
      usernameLabel: "Username",
      passwordLabel: "Password",
      confirmPasswordLabel: "Confirm Password",
      alreadyHaveAccount: "Already have an account?",
      dontHaveAccount: "Don't have an account?",
      loginInstead: "Login Instead",
      signupInstead: "Sign Up Instead",
    },
    footer: {
      madeWithLove: "Crafted with ❤️ by Your Name (or AI)",
      rightsReserved: "All Rights Reserved.",
    },
  },
  hi: {
    appName: "टेक्स्टमेट - आपका टेक्स्ट यूटिलिटी",
    heroSubtitle: "आसानी से अपने टेक्स्ट को बदलें और विश्लेषण करें।",
    placeholder: "यहां अपना टेक्स्ट दर्ज करें या पेस्ट करें...",
    buttons: {
      uppercase: "बड़े अक्षर",
      lowercase: "छोटे अक्षर",
      titlecase: "शीर्षक केस",
      reverse: "उल्टा करें",
      copy: "टेक्स्ट कॉपी करें",
      clear: "सभी साफ़ करें",
      analyze: "विश्लेषण करें",
      darkMode: "डार्क थीम",
      lightMode: "लाइट थीम",
      language: "भाषा",
      login: "लॉग इन करें",
      logout: "लॉग आउट",
      signup: "साइन अप करें",
      close: "बंद करें",
      confirm: "पुष्टि करें",
      submit: "जमा करें",
    },
    analysis: {
      summary: "आपके टेक्स्ट का सारांश",
      words: "शब्द",
      characters: "अक्षर (बिना स्पेस)",
      sentences: "वाक्य",
      readTime: "अनुमानित पढ़ने का समय",
      minutes: "मिनट पढ़ना",
    },
    messages: {
      copied: "टेक्स्ट क्लिपबोर्ड पर कॉपी हो गया!",
      copyFailed: "टेक्स्ट कॉपी करने में विफल रहा।",
      clearConfirm: "क्या आप वाकई सभी टेक्स्ट साफ़ करना चाहते हैं?",
      errorFetching: "ऑपरेशन करने में त्रुटि:",
      loading: "टेक्स्ट संसाधित हो रहा है...",
      noText: "ऑपरेशन करने के लिए कृपया कुछ टेक्स्ट दर्ज करें।",
      modalTitle: "कार्रवाई की पुष्टि करें",
      modalClearTextContent:
        "यह कार्रवाई इनपुट क्षेत्र से सभी टेक्स्ट को साफ़ कर देगी और विश्लेषण रीसेट कर देगी। क्या आप आगे बढ़ना चाहते हैं?",
      loginPrompt:
        "ऑपरेशन इतिहास जैसी सुविधाओं और अपने टेक्स्ट परिवर्तनों को सहेजने के लिए लॉग इन या साइन अप करें।",
      loginSuccess: "सफलतापूर्वक लॉग इन किया गया!",
      loginFailed: "लॉगिन विफल:",
      signupSuccess: "सफलतापूर्वक साइन अप किया गया! कृपया लॉग इन करें।",
      signupFailed: "साइन अप विफल:",
      logoutSuccess: "सफलतापूर्वक लॉग आउट किया गया!",
      usernameRequired: "उपयोगकर्ता नाम आवश्यक है।",
      passwordRequired: "पासवर्ड आवश्यक है।",
      passwordMismatch: "पासवर्ड मेल नहीं खाते।",
      sessionExpired:
        "सत्र समाप्त हो गया या अनधिकृत। कृपया फिर से लॉग इन करें।",
    },
    auth: {
      loginTitle: "टेक्स्टमेट में लॉग इन करें",
      signupTitle: "टेक्स्टमेट के लिए साइन अप करें",
      usernameLabel: "उपयोगकर्ता नाम",
      passwordLabel: "पासवर्ड",
      confirmPasswordLabel: "पासवर्ड की पुष्टि करें",
      alreadyHaveAccount: "पहले से ही एक खाता है?",
      dontHaveAccount: "खाता नहीं है?",
      loginInstead: "इसके बजाय लॉग इन करें",
      signupInstead: "इसके बजाय साइन अप करें",
    },
    footer: {
      madeWithLove: "आपके नाम (या एआई) द्वारा ❤️ से तैयार किया गया",
      rightsReserved: "सभी अधिकार सुरक्षित।",
    },
  },
  es: {
    appName: "TextMate - Tu Utilidad de Texto",
    heroSubtitle: "Transforma y analiza tu texto con facilidad.",
    placeholder: "Introduce o pega tu texto aquí...",
    buttons: {
      uppercase: "MAYÚSCULAS",
      lowercase: "minúsculas",
      titlecase: "Título Caso",
      reverse: "Invertir",
      copy: "Copiar Texto",
      clear: "Borrar Todo",
      analyze: "Analizar",
      darkMode: "Tema Oscuro",
      lightMode: "Tema Claro",
      language: "Idioma",
      login: "Iniciar Sesión",
      logout: "Cerrar Sesión",
      signup: "Registrarse",
      close: "Cerrar",
      confirm: "Confirmar",
      submit: "Enviar",
    },
    analysis: {
      summary: "Resumen de tu Texto",
      words: "Palabras",
      characters: "Caracteres (Sin Espacios)",
      sentences: "Oraciones",
      readTime: "Tiempo de Lectura Estimado",
      minutes: "min de lectura",
    },
    messages: {
      copied: "¡Texto copiado al portapapeles!",
      copyFailed: "Error al copiar texto.",
      clearConfirm: "¿Estás seguro de que quieres borrar todo el texto?",
      errorFetching: "Error al realizar la operación:",
      loading: "Procesando texto...",
      noText: "Por favor, introduce texto para realizar operaciones.",
      modalTitle: "Confirmar Acción",
      modalClearTextContent:
        "Esta acción borrará todo el texto del área de entrada y restablecerá el análisis. ¿Quieres continuar?",
      loginPrompt:
        "Inicia sesión o regístrate para acceder a funciones como el historial de operaciones y guardar tus transformaciones de texto.",
      loginSuccess: "¡Sesión iniciada con éxito!",
      loginFailed: "Error de inicio de sesión:",
      signupSuccess: "¡Registro exitoso! Por favor, inicia sesión.",
      signupFailed: "Error de registro:",
      logoutSuccess: "¡Sesión cerrada con éxito!",
      usernameRequired: "El nombre de usuario es obligatorio.",
      passwordRequired: "La contraseña es obligatoria.",
      passwordMismatch: "Las contraseñas no coinciden.",
      sessionExpired:
        "Sesión caducada o no autorizada. Por favor, inicie sesión de nuevo.",
    },
    auth: {
      loginTitle: "Iniciar Sesión en TextMate",
      signupTitle: "Registrarse en TextMate",
      usernameLabel: "Nombre de Usuario",
      passwordLabel: "Contraseña",
      confirmPasswordLabel: "Confirmar Contraseña",
      alreadyHaveAccount: "¿Ya tienes una cuenta?",
      dontHaveAccount: "¿No tienes una cuenta?",
      loginInstead: "Iniciar Sesión en su Lugar",
      signupInstead: "Registrarse en su Lugar",
    },
    footer: {
      madeWithLove: "Hecho con ❤️ por Tu Nombre (o IA)",
      rightsReserved: "Todos los derechos reservados.",
    },
  },
};

// --- Main App Component ---
function App() {
  // --- Text Processing States ---
  const [text, setText] = useState("");
  const [transformedText, setTransformedText] = useState("");
  const [wordCount, setWordCount] = useState(0);
  const [charCount, setCharCount] = useState(0);
  const [sentenceCount, setSentenceCount] = useState(0);
  const [readTime, setReadTime] = useState(0);

  // --- UI/Global States ---
  const [message, setMessage] = useState("");
  const [isDarkMode, setIsDarkMode] = useState(false);
  const [selectedLanguage, setSelectedLanguage] = useState("en");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [showConfirmModal, setShowConfirmModal] = useState(false);

  // --- Authentication States ---
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [showLoginModal, setShowLoginModal] = useState(false);
  const [showSignupModal, setShowSignupModal] = useState(false);
  const [authUsername, setAuthUsername] = useState("");
  const [authPassword, setAuthPassword] = useState("");
  const [authConfirmPassword, setAuthConfirmPassword] = useState("");
  const [authMessage, setAuthMessage] = useState(""); // Messages specific to auth modals

  // --- Refs ---
  const textAreaRef = useRef(null);
  const messageTimeoutRef = useRef(null);
  const errorTimeoutRef = useRef(null);
  const debounceTimeoutRef = useRef(null);

  // --- Backend API Base URL ---
  const API_BASE_URL =
    process.env.NODE_ENV === "production"
      ? window.location.origin
      : "http://localhost:5000"; // Ensure this matches your backend's port

  // --- Memoized Translation Getter ---
  const t = useCallback(
    (key) => {
      const keys = key.split(".");
      let currentTranslation = translations[selectedLanguage];
      for (let i = 0; i < keys.length; i++) {
        if (
          currentTranslation &&
          typeof currentTranslation === "object" &&
          keys[i] in currentTranslation
        ) {
          currentTranslation = currentTranslation[keys[i]];
        } else {
          return key;
        }
      }
      return currentTranslation || key;
    },
    [selectedLanguage]
  );

  // --- Helper Functions ---

  // Update Text Analysis (Client-side)
  const updateAnalysis = useCallback((currentText) => {
    if (currentText.trim() === "") {
      setWordCount(0);
      setCharCount(0);
      setSentenceCount(0);
      setReadTime(0);
      return;
    }
    const words = currentText
      .trim()
      .split(/\s+/)
      .filter((word) => word.length > 0);
    setWordCount(words.length);
    setCharCount(currentText.replace(/\s/g, "").length);
    const sentences = currentText
      .trim()
      .split(/[.!?]+\s*/)
      .filter((s) => s.length > 0)
      // Filter out sentences that are only whitespace after splitting
      .filter((s) => s.trim().length > 0);
    setSentenceCount(sentences.length);
    setReadTime(Math.ceil(words.length * 0.005));
  }, []);

  // --- Authentication Handlers ---
  const handleLoginSubmit = async (e) => {
    e.preventDefault();
    setAuthMessage("");
    if (!authUsername || !authPassword) {
      setAuthMessage(
        t("messages.usernameRequired") + " " + t("messages.passwordRequired")
      );
      return;
    }

    setLoading(true);
    try {
      const response = await axios.post(`${API_BASE_URL}/api/login`, {
        username: authUsername,
        password: authPassword,
      });

      if (response.data.success) {
        localStorage.setItem("token", response.data.token); // Store JWT token
        setIsLoggedIn(true);
        setShowLoginModal(false);
        setMessage(t("messages.loginSuccess"));
        setAuthUsername("");
        setAuthPassword("");
      } else {
        setAuthMessage(`${t("messages.loginFailed")} ${response.data.message}`);
      }
    } catch (err) {
      console.error("Login error:", err);
      setAuthMessage(
        `${t("messages.loginFailed")} ${
          err.response?.data?.message || err.message
        }`
      );
    } finally {
      setLoading(false);
    }
  };

  const handleSignupSubmit = async (e) => {
    e.preventDefault();
    setAuthMessage("");
    if (!authUsername || !authPassword || !authConfirmPassword) {
      setAuthMessage(
        t("messages.usernameRequired") + " " + t("messages.passwordRequired")
      );
      return;
    }
    if (authPassword !== authConfirmPassword) {
      setAuthMessage(t("messages.passwordMismatch"));
      return;
    }

    setLoading(true);
    try {
      const response = await axios.post(`${API_BASE_URL}/api/signup`, {
        username: authUsername,
        password: authPassword,
      });

      if (response.data.success) {
        setAuthMessage(t("messages.signupSuccess"));
        // Optionally, automatically log in after successful signup
        // or guide user to login. For now, we guide to login modal.
        setShowSignupModal(false);
        setShowLoginModal(true);
        setAuthUsername("");
        setAuthPassword("");
        setAuthConfirmPassword("");
      } else {
        setAuthMessage(
          `${t("messages.signupFailed")} ${response.data.message}`
        );
      }
    } catch (err) {
      console.error("Signup error:", err);
      setAuthMessage(
        `${t("messages.signupFailed")} ${
          err.response?.data?.message || err.message
        }`
      );
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem("token"); // Remove JWT token
    setIsLoggedIn(false);
    setMessage(t("messages.logoutSuccess"));
    // Clear any text data for privacy
    setText("");
    setTransformedText("");
    updateAnalysis(""); // Clear analysis results
  };

  // --- Effects ---

  // Check for existing token on component mount and attempt to validate (simple check)
  useEffect(() => {
    const token = localStorage.getItem("token");
    if (token) {
      // In a real app, you would send this token to a backend /validate endpoint
      // to check its validity and expiration without making a full login request.
      // For this demo, we'll assume its presence means logged in.
      // A more robust check might involve decoding the JWT locally (without verifying signature)
      // to check for expiration date.
      setIsLoggedIn(true);
    } else {
      setIsLoggedIn(false);
    }
  }, []);

  // Dark Mode Toggle Effect
  useEffect(() => {
    if (isDarkMode) {
      document.documentElement.classList.add("dark-mode"); // Apply to html for better global theming
      document.body.classList.add("bg-dark", "text-light");
      document.body.classList.remove("bg-light", "text-dark");
      localStorage.setItem("theme", "dark");
    } else {
      document.documentElement.classList.remove("dark-mode");
      document.body.classList.add("bg-light", "text-dark");
      document.body.classList.remove("bg-dark", "text-light");
      localStorage.setItem("theme", "light");
    }
  }, [isDarkMode]);

  // Initial Theme Load from Local Storage
  useEffect(() => {
    const savedTheme = localStorage.getItem("theme");
    if (savedTheme === "dark") {
      setIsDarkMode(true);
    } else {
      setIsDarkMode(false);
    }
  }, []);

  // Message and Error Display Timeout Effect
  useEffect(() => {
    if (message) {
      if (messageTimeoutRef.current) clearTimeout(messageTimeoutRef.current);
      messageTimeoutRef.current = setTimeout(() => setMessage(""), 3000);
    }
    if (error) {
      if (errorTimeoutRef.current) clearTimeout(errorTimeoutRef.current);
      errorTimeoutRef.current = setTimeout(() => setError(""), 5000);
    }
    return () => {
      if (messageTimeoutRef.current) clearTimeout(messageTimeoutRef.current);
      if (errorTimeoutRef.current) clearTimeout(errorTimeoutRef.current);
    };
  }, [message, error]);

  // Debounced Input Analysis Effect
  useEffect(() => {
    if (debounceTimeoutRef.current) clearTimeout(debounceTimeoutRef.current);
    debounceTimeoutRef.current = setTimeout(() => {
      updateAnalysis(text);
    }, 500);
    return () => {
      if (debounceTimeoutRef.current) clearTimeout(debounceTimeoutRef.current);
    };
  }, [text, updateAnalysis]);

  // Handle Text Area Changes
  const handleOnChange = (event) => {
    const newText = event.target.value;
    setText(newText);
    setTransformedText(""); // Clear transformed text when original text changes
  };

  // API Call Helper Function
  const performTextOperation = useCallback(
    async (endpoint, operationType) => {
      if (text.trim().length === 0) {
        setMessage(t("messages.noText"));
        setError(""); // Clear previous errors
        return;
      }

      setLoading(true);
      setError("");
      setMessage("");

      try {
        const token = localStorage.getItem("token"); // Get token for authorized request
        const headers = {};
        if (token) {
          // Only send Authorization header if token exists
          headers.Authorization = `Bearer ${token}`;
        }

        const response = await axios.post(
          `${API_BASE_URL}/api/${endpoint}`,
          { text },
          { headers } // Attach headers object
        );

        if (response.data.success) {
          setTransformedText(response.data.transformedText || "");
          if (operationType === "analyze") {
            const { analysis } = response.data;
            setWordCount(analysis.wordCount);
            setCharCount(analysis.charCount);
            setSentenceCount(analysis.sentenceCount);
            setReadTime(analysis.readTime);
          }
        } else {
          setError(
            `${t("messages.errorFetching")} ${
              response.data.message || "Unknown error."
            }`
          );
          setTransformedText("");
        }
      } catch (err) {
        console.error(`Error during ${operationType} operation:`, err);
        setError(
          `${t("messages.errorFetching")} ${
            err.response?.data?.message || err.message
          }`
        );
        // Only force logout if it's explicitly an unauthorized error for a protected route
        if (err.response && err.response.status === 401 && isLoggedIn) {
          setMessage(t("messages.sessionExpired"));
          handleLogout(); // Force logout due to invalid/expired token
          setShowLoginModal(true); // Show login modal
        }
      } finally {
        setLoading(false);
      }
    },
    [text, t, API_BASE_URL, isLoggedIn, updateAnalysis, handleLogout]
  );

  // Button Handlers
  const handleUpperCase = () => performTextOperation("uppercase", "uppercase");
  const handleLowerCase = () => performTextOperation("lowercase", "lowercase");
  const handleTitleCase = () => performTextOperation("titlecase", "titlecase");
  const handleReverseText = () => performTextOperation("reverse", "reverse");
  // The 'Analyze' button logic is handled implicitly by updateAnalysis for UI feedback,
  // but a server-side analysis call (performTextOperation("analyse", "analyze")) could be added
  // if more complex server-side analysis is needed.

  // Clear Text Confirmation
  const handleClearText = () => setShowConfirmModal(true);
  const confirmClear = () => {
    setText("");
    setTransformedText("");
    updateAnalysis("");
    setMessage("");
    setError("");
    if (textAreaRef.current) textAreaRef.current.focus();
    setShowConfirmModal(false);
  };
  const cancelClear = () => setShowConfirmModal(false);

  // Copy Text
  const handleCopyText = () => {
    if (text.length === 0 && transformedText.length === 0) {
      setMessage(t("messages.noText"));
      return;
    }
    const textToCopy = transformedText || text;
    if (textAreaRef.current) {
      const originalValue = textAreaRef.current.value;
      textAreaRef.current.value = textToCopy;
      textAreaRef.current.select();
      try {
        const successful = document.execCommand("copy");
        setMessage(
          successful ? t("messages.copied") : t("messages.copyFailed")
        );
      } catch (err) {
        console.error("Failed to copy text using execCommand:", err);
        setMessage(t("messages.copyFailed"));
      } finally {
        textAreaRef.current.value = originalValue;
        textAreaRef.current.blur();
      }
    }
  };

  // --- Function to Toggle Dark Mode ---
  const toggleDarkMode = () => {
    setIsDarkMode((prevMode) => !prevMode);
  };

  // --- Function to Change Language ---
  const handleLanguageChange = (event) => {
    setSelectedLanguage(event.target.value);
  };

  // --- Main Component Render ---
  return (
    <>
      {/* Bootstrap CSS CDN */}
      <link
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
        rel="stylesheet"
        crossOrigin="anonymous"
      ></link>

      {/* Font Awesome for Icons */}
      <link
        rel="stylesheet"
        href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css"
        crossOrigin="anonymous"
        referrerPolicy="no-referrer"
      />

      {/* Custom Styles */}
      <style>
        {`
        /* Global Styles */
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

        html, body, #root {
            height: 100%; /* Ensure html, body, and root div take full height */
            margin: 0;
            padding: 0;
            overflow-x: hidden; /* Prevent horizontal scrolling for the whole page */
        }

        body {
          font-family: 'Inter', sans-serif;
          transition: background-color 0.3s ease, color 0.3s ease;
          line-height: 1.6;
        }

        /* Outer wrapper for full screen background and centering content */
        .app-outer-wrapper {
            display: flex;
            flex-direction: column; /* Stack content vertically */
            align-items: center; /* Center content horizontally */
            width: 100vw; /* Occupy full viewport width */
            min-height: 100vh; /* Occupy full viewport height */
            padding: 0; /* No padding here, handled by app-container */
        }

        /* Background gradients */
        .bg-gradient-light {
          background: linear-gradient(135deg, #f0f2f5, #e0e4eb);
        }
        .bg-gradient-dark {
          background: linear-gradient(135deg, #1a202c, #2d3748);
          color: #e0e4eb; /* Light text for dark background */
        }

        /* Main content container with max-width and internal padding */
        .app-container {
            width: 100%; /* Take full width up to max-width */
            max-width: 1200px; /* Max width for content on large screens */
            padding: 0 1rem; /* Default horizontal padding */
            box-sizing: border-box; /* Include padding in element's total width/height */
        }

        /* Responsive padding for app-container */
        @media (min-width: 576px) {
            .app-container { padding: 0 1.5rem; }
        }
        @media (min-width: 768px) {
            .app-container { padding: 0 3rem; }
        }
        @media (min-width: 992px) {
            .app-container { padding: 0 5rem; }
        }

        /* TextMate specific gradient for app name */
        .text-mate-gradient {
          background: linear-gradient(45deg, #007bff, #00aaff);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
        }

        /* Custom Button Styles */
        .btn-primary-custom {
          background: linear-gradient(45deg, #007bff, #00c0ff);
          border: none;
          transition: all 0.3s ease;
          box-shadow: 0 4px 12px rgba(0, 123, 255, 0.2);
          border-radius: 0.75rem;
          padding: 0.75rem 1.25rem;
          font-weight: 600;
        }
        .btn-primary-custom:hover {
          transform: translateY(-3px);
          box-shadow: 0 8px 20px rgba(0, 123, 255, 0.4);
          background: linear-gradient(45deg, #0056b3, #0099e6);
        }

        .btn-outline-primary-custom {
          border-color: #007bff;
          color: #007bff;
          transition: all 0.3s ease;
          border-radius: 0.75rem;
          padding: 0.75rem 1.25rem;
          font-weight: 600;
        }
        .btn-outline-primary-custom:hover {
          background-color: #007bff;
          color: white;
          box-shadow: 0 4px 12px rgba(0, 123, 255, 0.2);
        }

        .btn-danger-custom {
          background-color: #dc3545;
          border: none;
          transition: all 0.3s ease;
          box-shadow: 0 4px 12px rgba(220, 53, 69, 0.2);
          border-radius: 0.75rem;
          padding: 0.75rem 1.25rem;
          font-weight: 600;
        }
        .btn-danger-custom:hover {
          transform: translateY(-3px);
          box-shadow: 0 8px 20px rgba(220, 53, 69, 0.4);
          background-color: #c82333;
        }

        /* Card Styling */
        .card-custom {
          border-radius: 1rem;
          transition: all 0.3s ease;
          box-shadow: 0 8px 25px rgba(0, 0, 0, 0.1);
        }
        .card-custom.dark-mode {
          background-color: #343a40 !important;
          border-color: #454d55 !important;
          box-shadow: 0 8px 25px rgba(0, 0, 0, 0.3);
        }

        /* Form Control Styling */
        .form-control-custom {
          border-radius: 0.75rem;
          padding: 1.25rem;
          transition: all 0.3s ease;
        }
        .form-control-custom:focus {
          border-color: #007bff;
          box-shadow: 0 0 0 0.25rem rgba(0, 123, 255, 0.25);
        }
        .form-label { font-weight: 600; } /* Make labels stand out */

        /* Animations */
        @keyframes fadeIn { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes pulse { 0% { transform: scale(1); } 50% { transform: scale(1.05); } 100% { transform: scale(1); } }
        .animate-fade-in { animation: fadeIn 0.5s ease-out forwards; }
        .animate-pulse { animation: pulse 1.5s infinite ease-in-out; }

        /* Language Dropdown */
        .form-select-sm {
            padding-top: 0.5rem;
            padding-bottom: 0.5rem;
            font-size: 0.875rem;
        }

        /* Modal Specific Styles */
        .modal-content.card-custom {
            border-radius: 1rem;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
        }
        .modal-backdrop.show { opacity: 0.6; }
        .modal.fade .modal-dialog { transform: translate(0, -25%); transition: transform 0.3s ease-out; }
        .modal.show .modal-dialog { transform: translate(0, 0); }
        .btn-close { filter: ${
          isDarkMode ? "invert(1)" : "none"
        }; } /* Ensure close button is visible in dark mode */


        /* Responsive Adjustments */
        @media (max-width: 767.98px) {
            .btn-group-mobile-stack .col-6 { flex: 0 0 100%; max-width: 100%; }
            .btn-group-mobile-stack .col-6:not(:last-child) { margin-bottom: 0.75rem; }
            .analysis-card-col { margin-bottom: 1.5rem; }
            .analysis-card-col:last-child { margin-bottom: 0; }
        }
        `}
      </style>

      {/* Confirmation Modal */}
      <div
        className={`modal fade ${showConfirmModal ? "show d-block" : ""}`}
        tabIndex="-1"
        role="dialog"
        aria-hidden={!showConfirmModal}
      >
        <div className="modal-dialog modal-dialog-centered" role="document">
          <div
            className={`modal-content card-custom ${
              isDarkMode ? "bg-secondary text-light" : "bg-white text-dark"
            }`}
          >
            <div className="modal-header border-0 pb-0">
              <h5 className="modal-title fw-bold">
                {t("messages.modalTitle")}
              </h5>
              <button
                type="button"
                className={`btn-close ${isDarkMode ? "btn-close-white" : ""}`}
                aria-label="Close"
                onClick={cancelClear}
              ></button>
            </div>
            <div className="modal-body text-muted pt-0">
              {t("messages.modalClearTextContent")}
            </div>
            <div className="modal-footer border-0 pt-0">
              <button
                type="button"
                className="btn btn-outline-secondary rounded-pill px-4"
                onClick={cancelClear}
              >
                {t("buttons.close")}
              </button>
              <button
                type="button"
                className="btn btn-danger-custom rounded-pill px-4 text-white"
                onClick={confirmClear}
              >
                {t("buttons.confirm")}
              </button>
            </div>
          </div>
        </div>
      </div>
      {showConfirmModal && <div className="modal-backdrop fade show"></div>}

      {/* Login Modal */}
      <div
        className={`modal fade ${showLoginModal ? "show d-block" : ""}`}
        tabIndex="-1"
        role="dialog"
        aria-hidden={!showLoginModal}
      >
        <div className="modal-dialog modal-dialog-centered" role="document">
          <div
            className={`modal-content card-custom ${
              isDarkMode ? "bg-secondary text-light" : "bg-white text-dark"
            }`}
          >
            <div className="modal-header border-0">
              <h5 className="modal-title fw-bold">{t("auth.loginTitle")}</h5>
              <button
                type="button"
                className={`btn-close ${isDarkMode ? "btn-close-white" : ""}`}
                aria-label="Close"
                onClick={() => {
                  setShowLoginModal(false);
                  setAuthMessage("");
                }} // Clear message on close
              ></button>
            </div>
            <div className="modal-body">
              {authMessage && (
                <div className="alert alert-info py-2" role="alert">
                  {authMessage}
                </div>
              )}
              <form onSubmit={handleLoginSubmit}>
                <div className="mb-3">
                  <label htmlFor="loginUsername" className="form-label">
                    {t("auth.usernameLabel")}
                  </label>
                  <input
                    type="text"
                    className={`form-control form-control-custom ${
                      isDarkMode ? "bg-dark text-light border-secondary" : ""
                    }`}
                    id="loginUsername"
                    value={authUsername}
                    onChange={(e) => setAuthUsername(e.target.value)}
                    required
                  />
                </div>
                <div className="mb-3">
                  <label htmlFor="loginPassword" className="form-label">
                    {t("auth.passwordLabel")}
                  </label>
                  <input
                    type="password"
                    className={`form-control form-control-custom ${
                      isDarkMode ? "bg-dark text-light border-secondary" : ""
                    }`}
                    id="loginPassword"
                    value={authPassword}
                    onChange={(e) => setAuthPassword(e.target.value)}
                    required
                  />
                </div>
                <div className="d-grid gap-2 mb-3">
                  <button
                    type="submit"
                    className="btn btn-primary-custom text-white"
                    disabled={loading}
                  >
                    {loading ? (
                      <span
                        className="spinner-border spinner-border-sm"
                        role="status"
                        aria-hidden="true"
                      ></span>
                    ) : (
                      t("buttons.login")
                    )}
                  </button>
                </div>
                <div className="text-center">
                  <p className="text-muted mb-1">{t("auth.dontHaveAccount")}</p>
                  <button
                    type="button"
                    className="btn btn-link text-decoration-none"
                    onClick={() => {
                      setShowLoginModal(false);
                      setShowSignupModal(true);
                      setAuthMessage("");
                    }}
                  >
                    {t("auth.signupInstead")}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      </div>
      {showLoginModal && <div className="modal-backdrop fade show"></div>}

      {/* Signup Modal */}
      <div
        className={`modal fade ${showSignupModal ? "show d-block" : ""}`}
        tabIndex="-1"
        role="dialog"
        aria-hidden={!showSignupModal}
      >
        <div className="modal-dialog modal-dialog-centered" role="document">
          <div
            className={`modal-content card-custom ${
              isDarkMode ? "bg-secondary text-light" : "bg-white text-dark"
            }`}
          >
            <div className="modal-header border-0">
              <h5 className="modal-title fw-bold">{t("auth.signupTitle")}</h5>
              <button
                type="button"
                className={`btn-close ${isDarkMode ? "btn-close-white" : ""}`}
                aria-label="Close"
                onClick={() => {
                  setShowSignupModal(false);
                  setAuthMessage("");
                }} // Clear message on close
              ></button>
            </div>
            <div className="modal-body">
              {authMessage && (
                <div className="alert alert-info py-2" role="alert">
                  {authMessage}
                </div>
              )}
              <form onSubmit={handleSignupSubmit}>
                <div className="mb-3">
                  <label htmlFor="signupUsername" className="form-label">
                    {t("auth.usernameLabel")}
                  </label>
                  <input
                    type="text"
                    className={`form-control form-control-custom ${
                      isDarkMode ? "bg-dark text-light border-secondary" : ""
                    }`}
                    id="signupUsername"
                    value={authUsername}
                    onChange={(e) => setAuthUsername(e.target.value)}
                    required
                  />
                </div>
                <div className="mb-3">
                  <label htmlFor="signupPassword" className="form-label">
                    {t("auth.passwordLabel")}
                  </label>
                  <input
                    type="password"
                    className={`form-control form-control-custom ${
                      isDarkMode ? "bg-dark text-light border-secondary" : ""
                    }`}
                    id="signupPassword"
                    value={authPassword}
                    onChange={(e) => setAuthPassword(e.target.value)}
                    required
                  />
                </div>
                <div className="mb-3">
                  <label htmlFor="confirmPassword" className="form-label">
                    {t("auth.confirmPasswordLabel")}
                  </label>
                  <input
                    type="password"
                    className={`form-control form-control-custom ${
                      isDarkMode ? "bg-dark text-light border-secondary" : ""
                    }`}
                    id="confirmPassword"
                    value={authConfirmPassword}
                    onChange={(e) => setAuthConfirmPassword(e.target.value)}
                    required
                  />
                </div>
                <div className="d-grid gap-2 mb-3">
                  <button
                    type="submit"
                    className="btn btn-primary-custom text-white"
                    disabled={loading}
                  >
                    {loading ? (
                      <span
                        className="spinner-border spinner-border-sm"
                        role="status"
                        aria-hidden="true"
                      ></span>
                    ) : (
                      t("buttons.signup")
                    )}
                  </button>
                </div>
                <div className="text-center">
                  <p className="text-muted mb-1">
                    {t("auth.alreadyHaveAccount")}
                  </p>
                  <button
                    type="button"
                    className="btn btn-link text-decoration-none"
                    onClick={() => {
                      setShowSignupModal(false);
                      setShowLoginModal(true);
                      setAuthMessage("");
                    }}
                  >
                    {t("auth.loginInstead")}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      </div>
      {showSignupModal && <div className="modal-backdrop fade show"></div>}

      {/* Main container for the entire application, handling background and full height */}
      <div
        className={`app-outer-wrapper ${
          isDarkMode ? "bg-gradient-dark" : "bg-gradient-light"
        }`}
      >
        {/* Main app content container, centered with max-width */}
        <div className="app-container py-5">
          {/* Header Section */}
          <header className="d-flex flex-column flex-md-row justify-content-between align-items-center py-4 mb-5 border-bottom border-secondary-subtle">
            <h1 className="display-3 fw-bolder text-mate-gradient mb-3 mb-md-0 animate__animated animate__fadeInDown">
              {t("appName")}
            </h1>
            <div className="d-flex align-items-center flex-wrap justify-content-center">
              {/* Language Selector */}
              <div className="dropdown me-3 mb-2 mb-sm-0">
                <select
                  id="language-select"
                  value={selectedLanguage}
                  onChange={handleLanguageChange}
                  aria-label={t("buttons.language")}
                  className={`form-select form-select-sm rounded-pill px-3 py-2 ${
                    isDarkMode
                      ? "bg-dark text-light border-secondary"
                      : "bg-white text-dark border-light"
                  }`}
                >
                  <option value="en">English</option>
                  <option value="hi">हिन्दी</option>
                  <option value="es">Español</option>
                </select>
              </div>

              {/* Dark/Light Mode Toggle */}
              <button
                onClick={toggleDarkMode}
                className={`btn ${
                  isDarkMode ? "btn-outline-light" : "btn-outline-dark"
                } rounded-pill d-flex align-items-center px-3 py-2 me-3 animate__animated animate__fadeIn`}
                aria-label={
                  isDarkMode ? t("buttons.lightMode") : t("buttons.darkMode")
                }
              >
                {isDarkMode ? (
                  <>
                    <i className="fas fa-sun me-2"></i>
                    <span className="d-none d-sm-inline">
                      {t("buttons.lightMode")}
                    </span>
                  </>
                ) : (
                  <>
                    <i className="fas fa-moon me-2"></i>
                    <span className="d-none d-sm-inline">
                      {t("buttons.darkMode")}
                    </span>
                  </>
                )}
              </button>

              {/* Login/Logout/Signup Buttons */}
              {isLoggedIn ? (
                <button
                  onClick={handleLogout}
                  className="btn btn-outline-danger rounded-pill d-flex align-items-center px-3 py-2 animate__animated animate__fadeIn"
                  aria-label={t("buttons.logout")}
                >
                  <i className="fas fa-sign-out-alt me-2"></i>
                  <span className="d-none d-sm-inline">
                    {t("buttons.logout")}
                  </span>
                </button>
              ) : (
                <>
                  <button
                    onClick={() => {
                      setShowLoginModal(true);
                      setAuthMessage("");
                    }} // Clear auth message on open
                    className="btn btn-outline-success rounded-pill d-flex align-items-center px-3 py-2 me-2 animate__animated animate__fadeIn"
                    aria-label={t("buttons.login")}
                  >
                    <i className="fas fa-sign-in-alt me-2"></i>
                    <span className="d-none d-sm-inline">
                      {t("buttons.login")}
                    </span>
                  </button>
                  <button
                    onClick={() => {
                      setShowSignupModal(true);
                      setAuthMessage("");
                    }} // Clear auth message on open
                    className="btn btn-primary-custom rounded-pill d-flex align-items-center px-3 py-2 animate__animated animate__fadeIn"
                    aria-label={t("buttons.signup")}
                  >
                    <i className="fas fa-user-plus me-2"></i>
                    <span className="d-none d-sm-inline">
                      {t("buttons.signup")}
                    </span>
                  </button>
                </>
              )}
            </div>
          </header>

          {/* Main Content Area */}
          <main
            className={`p-4 p-md-5 rounded-4 shadow-lg card-custom ${
              isDarkMode
                ? "bg-secondary text-light card-custom dark-mode"
                : "bg-white text-dark"
            }`}
          >
            <section className="text-center mb-5 animate__animated animate__fadeInUp">
              <p className="lead text-muted fst-italic mb-4">
                {t("heroSubtitle")}
              </p>
            </section>

            {/* Text Input Section - Always visible */}
            <div className="mb-5">
              <label
                htmlFor="text-area"
                className="form-label h4 text-primary mb-3 fw-bold"
              >
                Input Text
              </label>
              <textarea
                ref={textAreaRef}
                id="text-area"
                className={`form-control form-control-custom ${
                  isDarkMode ? "bg-dark text-light border-secondary" : ""
                }`}
                value={text}
                onChange={handleOnChange}
                placeholder={t("placeholder")}
                rows="10"
                aria-label="Text input area for analysis and transformation"
              ></textarea>
            </div>

            {/* Action Buttons Section - Always visible */}
            <div className="row g-3 mb-5 justify-content-center btn-group-mobile-stack">
              <div className="col-6 col-md-4 col-lg-2">
                <button
                  onClick={handleUpperCase}
                  className="btn btn-primary-custom w-100 text-white"
                  disabled={loading}
                  aria-label={t("buttons.uppercase")}
                >
                  {loading ? (
                    <span
                      className="spinner-border spinner-border-sm"
                      role="status"
                      aria-hidden="true"
                    ></span>
                  ) : (
                    t("buttons.uppercase")
                  )}
                </button>
              </div>
              <div className="6 col-md-4 col-lg-2">
                <button
                  onClick={handleLowerCase}
                  className="btn btn-primary-custom w-100 text-white"
                  disabled={loading}
                  aria-label={t("buttons.lowercase")}
                >
                  {loading ? (
                    <span
                      className="spinner-border spinner-border-sm"
                      role="status"
                      aria-hidden="true"
                    ></span>
                  ) : (
                    t("buttons.lowercase")
                  )}
                </button>
              </div>
              <div className="col-6 col-md-4 col-lg-2">
                <button
                  onClick={handleTitleCase}
                  className="btn btn-primary-custom w-100 text-white"
                  disabled={loading}
                  aria-label={t("buttons.titlecase")}
                >
                  {loading ? (
                    <span
                      className="spinner-border spinner-border-sm"
                      role="status"
                      aria-hidden="true"
                    ></span>
                  ) : (
                    t("buttons.titlecase")
                  )}
                </button>
              </div>
              <div className="col-6 col-md-4 col-lg-2">
                <button
                  onClick={handleReverseText}
                  className="btn btn-primary-custom w-100 text-white"
                  disabled={loading}
                  aria-label={t("buttons.reverse")}
                >
                  {loading ? (
                    <span
                      className="spinner-border spinner-border-sm"
                      role="status"
                      aria-hidden="true"
                    ></span>
                  ) : (
                    t("buttons.reverse")
                  )}
                </button>
              </div>
              <div className="col-6 col-md-4 col-lg-2">
                <button
                  onClick={handleCopyText}
                  className="btn btn-outline-primary-custom w-100"
                  aria-label={t("buttons.copy")}
                >
                  {t("buttons.copy")}
                </button>
              </div>
              <div className="col-6 col-md-4 col-lg-2">
                <button
                  onClick={handleClearText}
                  className="btn btn-danger-custom w-100 text-white"
                  aria-label={t("buttons.clear")}
                >
                  {t("buttons.clear")}
                </button>
              </div>
            </div>

            {/* Messages and Errors Display */}
            {loading && (
              <div
                className="text-center py-3 mb-4 text-primary animate-pulse"
                role="status"
                aria-live="polite"
              >
                <div className="spinner-grow text-primary me-2" role="status">
                  <span className="visually-hidden">
                    {t("messages.loading")}
                  </span>
                </div>
                <span className="fw-bold">{t("messages.loading")}</span>
              </div>
            )}
            {message && (
              <div
                className="alert alert-info border-0 rounded-3 shadow-sm animate__animated animate__fadeInDown px-4 py-3"
                role="alert"
                aria-live="polite"
              >
                <p className="fw-bold mb-0 fs-6">
                  <i className="fas fa-check-circle me-2"></i>
                  {message}
                </p>
              </div>
            )}
            {error && (
              <div
                className="alert alert-danger border-0 rounded-3 shadow-sm animate__animated animate__fadeInDown px-4 py-3"
                role="alert"
                aria-live="assertive"
              >
                <p className="fw-bold mb-0 fs-6">
                  <i className="fas fa-exclamation-triangle me-2"></i>Error!{" "}
                  {error}
                </p>
              </div>
            )}

            {/* Transformed Text Display (if any) */}
            {transformedText && (
              <div className="mb-5 p-4 rounded-4 border border-primary bg-primary bg-opacity-10 animate__animated animate__fadeIn">
                <h3 className="h5 text-primary mb-3 fw-bold">
                  Transformed Text
                </h3>
                <p className="text-break text-secondary-emphasis">
                  {transformedText}
                </p>
              </div>
            )}

            {/* Text Analysis Section - Always visible */}
            <div className="mb-5">
              <h2 className="h4 text-primary mb-4 fw-bold">
                {t("analysis.summary")}
              </h2>
              <div className="row g-4">
                <div className="col-12 col-sm-6 col-lg-3 analysis-card-col">
                  <div
                    className={`card card-custom h-100 ${
                      isDarkMode ? "dark-mode" : ""
                    }`}
                  >
                    <div className="card-body text-center">
                      <h3 className="card-title h6 text-muted mb-2">
                        {t("analysis.words")}
                      </h3>
                      <p className="card-text display-5 fw-bold text-primary">
                        {wordCount}
                      </p>
                    </div>
                  </div>
                </div>
                <div className="col-12 col-sm-6 col-lg-3 analysis-card-col">
                  <div
                    className={`card card-custom h-100 ${
                      isDarkMode ? "dark-mode" : ""
                    }`}
                  >
                    <div className="card-body text-center">
                      <h3 className="card-title h6 text-muted mb-2">
                        {t("analysis.characters")}
                      </h3>
                      <p className="card-text display-5 fw-bold text-primary">
                        {charCount}
                      </p>
                    </div>
                  </div>
                </div>
                <div className="col-12 col-sm-6 col-lg-3 analysis-card-col">
                  <div
                    className={`card card-custom h-100 ${
                      isDarkMode ? "dark-mode" : ""
                    }`}
                  >
                    <div className="card-body text-center">
                      <h3 className="card-title h6 text-muted mb-2">
                        {t("analysis.sentences")}
                      </h3>
                      <p className="card-text display-5 fw-bold text-primary">
                        {sentenceCount}
                      </p>
                    </div>
                  </div>
                </div>
                <div className="col-12 col-sm-6 col-lg-3 analysis-card-col">
                  <div
                    className={`card card-custom h-100 ${
                      isDarkMode ? "dark-mode" : ""
                    }`}
                  >
                    <div className="card-body text-center">
                      <h3 className="card-title h6 text-muted mb-2">
                        {t("analysis.readTime")}
                      </h3>
                      <p className="card-text display-5 fw-bold text-primary">
                        {readTime}{" "}
                        <small className="text-muted h6">
                          {t("analysis.minutes")}
                        </small>
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Login Prompt - Visible only if not logged in */}
            {!isLoggedIn && (
              <div
                className="alert alert-warning text-center rounded-3 shadow-sm my-5 py-4 animate__animated animate__fadeInUp"
                role="alert"
              >
                <i className="fas fa-exclamation-circle me-2"></i>
                <h4 className="alert-heading">{t("messages.loginPrompt")}</h4>
                <p className="mb-0">
                  Your text operations will not be saved if you are not logged
                  in. Log in or sign up to access features like operation
                  history and to save your text transformations.
                </p>
              </div>
            )}

            {/* How It Works Section (visible regardless of login status) */}
            <section className="mt-5 pt-5 border-top border-secondary-subtle">
              <h2 className="h4 text-primary text-center mb-4 fw-bold">
                How It Works
              </h2>
              <div className="row g-4 text-muted">
                <div className="col-12 col-md-6 animate__animated animate__fadeInLeft">
                  <h3 className="h5 text-info mb-3 fw-semibold">
                    Client-Side Processing for Speed
                  </h3>
                  <p className="mb-2">
                    Word, character, and sentence counts are calculated
                    instantly right in your browser. This ensures a smooth and
                    responsive experience as you type, even without an internet
                    connection (though transformations still require the
                    server).
                  </p>
                  <p className="mb-2">
                    This approach minimizes network requests for basic analysis,
                    reducing latency and improving perceived performance,
                    especially for mobile users or those with slower
                    connections.
                  </p>
                  <ul className="list-unstyled ps-3 mt-3">
                    <li>
                      <i className="fas fa-check-circle text-success me-2"></i>
                      Real-time word and character count updates.
                    </li>
                    <li>
                      <i className="fas fa-check-circle text-success me-2"></i>
                      Efficient sentence detection for accurate summaries.
                    </li>
                    <li>
                      <i className="fas fa-check-circle text-success me-2"></i>
                      Debounced input to prevent excessive calculations during
                      rapid typing.
                    </li>
                  </ul>
                </div>
                <div className="col-12 col-md-6 animate__animated animate__fadeInRight">
                  <h3 className="h5 text-info mb-3 fw-semibold">
                    Robust Backend Operations
                  </h3>
                  <p className="mb-2">
                    Text transformations like uppercase, lowercase, title case,
                    and text reversal are handled by a powerful Node.js Express
                    backend. This offloads heavier processing, keeps the
                    frontend lightweight, and allows for future expansion with
                    more complex NLP tasks.
                  </p>
                  <p className="mb-2">
                    The backend also logs operations to a MongoDB database,
                    associated with a user if logged in, providing a history of
                    usage. This MERN stack integration demonstrates a scalable
                    and maintainable architecture.
                  </p>
                  <ul className="list-unstyled ps-3 mt-3">
                    <li>
                      <i className="fas fa-check-circle text-success me-2"></i>
                      Secure API endpoints for text transformations.
                    </li>
                    <li>
                      <i className="fas fa-check-circle text-success me-2"></i>
                      MongoDB integration for logging and history (for logged-in
                      users).
                    </li>
                    <li>
                      <i className="fas fa-check-circle text-success me-2"></i>
                      Optimized API responses for faster loading.
                    </li>
                  </ul>
                </div>
              </div>
              <div className="mt-5 text-center">
                <p className="text-sm fst-italic text-secondary-emphasis">
                  "Performance and user experience are at the heart of
                  TextMate's design."
                </p>
              </div>
            </section>
          </main>

          {/* Footer Section */}
          <footer className="mt-5 text-center text-muted small py-4 border-top border-secondary-subtle">
            <p className="mb-1">{t("footer.madeWithLove")}</p>
            <p>
              &copy; {new Date().getFullYear()} TextMate.{" "}
              {t("footer.rightsReserved")}
            </p>
            <p className="mt-2 text-xs">
              GitHub Repository:{" "}
              <a
                href="https://github.com/mohityadavbkbiet/TextMate"
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary text-decoration-none fw-semibold"
              >
                mohityadavbkbiet/TextUtils
              </a>
            </p>
          </footer>
        </div>
      </div>

      {/* Bootstrap Bundle with Popper */}
      <script
        src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"
        crossOrigin="anonymous"
      ></script>
    </>
  );
}

export default App;
