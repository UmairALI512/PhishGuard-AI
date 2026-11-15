
import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js";

import {
    getAuth,
    createUserWithEmailAndPassword,
    signInWithEmailAndPassword,
    signOut,
    onAuthStateChanged
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js";

const firebaseConfig = {
    apiKey: "AIzaSyCXjBajnl7JhbIIBOppMsriFnIIYYW7pa4",
    authDomain: "phishguard-ai-18415.firebaseapp.com",
    projectId: "phishguard-ai-18415",
    storageBucket: "phishguard-ai-18415.firebasestorage.app",
    messagingSenderId: "691203544505",
    appId: "1:691203544505:web:23ecea52f9dcdd71385268",
    measurementId: "G-SMH87M4XTF"
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);

export {
    auth,
    createUserWithEmailAndPassword,
    signInWithEmailAndPassword,
    signOut,
    onAuthStateChanged
};
