import React from "react";

// In your local Vite project, `import { createClient } from '@supabase/supabase-js'` is the standard way.

// This CDN import is used to ensure compatibility in different preview environments.

import { createClient } from "https://cdn.jsdelivr.net/npm/@supabase/supabase-js/+esm";

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;

const supabaseKey = import.meta.env.VITE_SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseKey) {
  console.error(
    "Supabase URL or Key is missing. Make sure to set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY in your .env.local file."
  );
}

const supabase = createClient(supabaseUrl, supabaseKey);

// --- Crypto Helper Functions ---
async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await window.crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  return window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: enc.encode(salt),
      iterations: 100000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

async function encrypt(text, key) {
  const enc = new TextEncoder();
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encryptedContent = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    enc.encode(text)
  );
  const result = new Uint8Array(
    iv.length + new Uint8Array(encryptedContent).length
  );
  result.set(iv, 0);
  result.set(new Uint8Array(encryptedContent), iv.length);
  return btoa(String.fromCharCode.apply(null, result));
}

async function decrypt(encryptedText, key) {
  try {
    const binaryString = atob(encryptedText);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    const iv = bytes.slice(0, 12);
    const encryptedContent = bytes.slice(12);
    const decryptedContent = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      key,
      encryptedContent
    );
    return new TextDecoder().decode(decryptedContent);
  } catch (e) {
    console.error("Decryption failed:", e);
    return null;
  }
}

function generateSecurePassword() {
  const length = 18;
  const lower = "abcdefghijklmnopqrstuvwxyz",
    upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    numbers = "0123456789",
    symbols = "!@#$%^&*()_+~`|}{[]:;?><,./-=";
  let password = [
    lower[Math.floor(Math.random() * lower.length)],
    upper[Math.floor(Math.random() * upper.length)],
    numbers[Math.floor(Math.random() * numbers.length)],
    symbols[Math.floor(Math.random() * symbols.length)],
  ];
  const allChars = lower + upper + numbers + symbols;
  for (let i = password.length; i < length; i++) {
    password.push(allChars[Math.floor(Math.random() * allChars.length)]);
  }
  return password.sort(() => Math.random() - 0.5).join("");
}

// --- Main App Component ---
export default function App() {
  const [session, setSession] = React.useState(null);

  React.useEffect(() => {
    supabase.auth.getSession().then(({ data: { session } }) => {
      setSession(session);
    });
    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((_event, session) => {
      setSession(session);
    });
    return () => subscription.unsubscribe();
  }, []);

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 to-slate-800 text-slate-100 flex items-center justify-center font-sans p-4 selection:bg-violet-500 selection:text-white">
      <div className="w-full max-w-3xl mx-auto backdrop-blur-sm bg-black/30 rounded-2xl shadow-2xl shadow-black/40 border border-white/10">
        <div className="p-6 sm:p-8">
          {!session ? (
            <Auth />
          ) : (
            <Dashboard key={session.user.id} session={session} />
          )}
        </div>
      </div>
    </div>
  );
}

// --- Authentication Component ---
function Auth() {
  const [loading, setLoading] = React.useState(false);
  const [email, setEmail] = React.useState("");
  const [message, setMessage] = React.useState("");

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage("");
    try {
      const { error } = await supabase.auth.signInWithOtp({ email });
      if (error) throw error;
      setMessage("Check your email for the magic link!");
    } catch (error) {
      setMessage(`Error: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleOAuthLogin = async (provider) => {
    setLoading(true);
    const { error } = await supabase.auth.signInWithOAuth({ provider });
    if (error) {
      setMessage(`Error: ${error.message}`);
    }
    setLoading(false);
  };

  return (
    <div className="flex flex-col gap-6 animate-fade-in">
      <div className="text-center">
        <h1 className="text-3xl sm:text-4xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-violet-400 to-purple-500">
          Secure Vault
        </h1>
        <p className="text-slate-400 mt-2">
          Passwordless sign-in for ultimate security.
        </p>
      </div>
      <form onSubmit={handleLogin} className="flex flex-col gap-4">
        <input
          className="bg-slate-800/60 px-4 py-3 rounded-lg border border-white/10 focus:outline-none focus:ring-2 focus:ring-violet-500 transition-all duration-300"
          type="email"
          placeholder="Enter your email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />
        <button
          className="bg-violet-600 hover:bg-violet-700 font-bold py-3 px-4 rounded-lg transition-all duration-300 disabled:opacity-50 transform hover:scale-105 active:scale-100"
          disabled={loading}
        >
          {loading ? "Sending..." : "Send Magic Link"}
        </button>
      </form>
      <div className="relative flex py-2 items-center">
        <div className="flex-grow border-t border-slate-700"></div>
        <span className="flex-shrink mx-4 text-slate-400 text-xs">OR</span>
        <div className="flex-grow border-t border-slate-700"></div>
      </div>
      <button
        onClick={() => handleOAuthLogin("google")}
        className="bg-white/10 hover:bg-white/20 font-bold py-3 px-4 rounded-lg transition-all duration-300 flex items-center justify-center gap-3"
        disabled={loading}
      >
        <i className="fa-brands fa-google"></i>
        <span>Sign in with Google</span>
      </button>
      {message && <p className="text-center text-green-400 mt-2">{message}</p>}
    </div>
  );
}

// --- Dashboard Component ---
function Dashboard({ session }) {
  const [decryptionKey, setDecryptionKey] = React.useState(null);
  const [error, setError] = React.useState(null);
  const [passwords, setPasswords] = React.useState([]);
  const [loadingPasswords, setLoadingPasswords] = React.useState(true);

  const [website, setWebsite] = React.useState("");
  const [username, setUsername] = React.useState("");
  const [newPassword, setNewPassword] = React.useState("");
  const [iconFile, setIconFile] = React.useState(null);
  const [searchQuery, setSearchQuery] = React.useState("");

  const [revealedPassword, setRevealedPassword] = React.useState({});
  const [confirmingDeleteId, setConfirmingDeleteId] = React.useState(null);
  const [copiedInfo, setCopiedInfo] = React.useState({ id: null, timer: null });

  // Edit State
  const [editingPasswordId, setEditingPasswordId] = React.useState(null);
  const [editingData, setEditingData] = React.useState({
    username: "",
    password: "",
  });

  // MFA State
  const [isMfaEnabled, setIsMfaEnabled] = React.useState(false);
  const [showMfaSetup, setShowMfaSetup] = React.useState(false);
  const [isMfaModalOpen, setIsMfaModalOpen] = React.useState(false);
  const [passwordToVerify, setPasswordToVerify] = React.useState(null);

  const getProfile = React.useCallback(async () => {
    const { data, error } = await supabase
      .from("profiles")
      .select("mfa_enabled")
      .eq("id", session.user.id)
      .single();
    if (error && error.code !== "PGRST116") {
      // PGRST116 means no row found
      console.error("Error fetching profile:", error);
    } else if (data) {
      setIsMfaEnabled(data.mfa_enabled);
    } else {
      setIsMfaEnabled(false);
    }
  }, [session.user.id]);

  const getPasswords = React.useCallback(async () => {
    setLoadingPasswords(true);
    const { data, error } = await supabase
      .from("passwords")
      .select("id, website_url, username, encrypted_password, icon_url");
    if (error) {
      setError("Could not fetch passwords.");
    } else {
      setPasswords(data);
    }
    setLoadingPasswords(false);
  }, []);

  React.useEffect(() => {
    getProfile();
    getPasswords();
    const channel = supabase
      .channel("passwords")
      .on(
        "postgres_changes",
        { event: "*", schema: "public", table: "passwords" },
        () => getPasswords()
      )
      .subscribe();
    return () => {
      supabase.removeChannel(channel);
    };
  }, [getPasswords, getProfile]);

  const filteredPasswords = React.useMemo(() => {
    return passwords.filter(
      (p) =>
        p.website_url.toLowerCase().includes(searchQuery.toLowerCase()) ||
        p.username.toLowerCase().includes(searchQuery.toLowerCase())
    );
  }, [passwords, searchQuery]);

  const setKeyAndUnlock = async (keyfileContent) => {
    if (!keyfileContent) {
      setError("Key file content cannot be empty.");
      return;
    }
    setError(null);
    const key = await deriveKey(keyfileContent, session.user.email);
    setDecryptionKey(key);
  };

  const handleGenerateKeyfile = async () => {
    const randomBytes = window.crypto.getRandomValues(new Uint8Array(32));
    const keyfileContent = btoa(String.fromCharCode.apply(null, randomBytes));
    const blob = new Blob([keyfileContent], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "vault-key.txt";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    await setKeyAndUnlock(keyfileContent);
  };

  const handleFileUnlock = async (event) => {
    const file = event.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = async (e) => {
      await setKeyAndUnlock(e.target.result.trim());
    };
    reader.readAsText(file);
    event.target.value = null;
  };

  const handleAddPassword = async (e) => {
    e.preventDefault();
    if (!website || !username || !newPassword) {
      setError("Please fill all fields.");
      return;
    }
    setError(null);

    let uploadedIconUrl = null;
    if (iconFile) {
      const fileExt = iconFile.name.split(".").pop();
      const fileName = `${Math.random()}.${fileExt}`;
      const filePath = `${session.user.id}/${fileName}`;

      const { error: uploadError } = await supabase.storage
        .from("entry-icons")
        .upload(filePath, iconFile);

      if (uploadError) {
        setError("Failed to upload icon.");
        return;
      }

      const { data: urlData } = supabase.storage
        .from("entry-icons")
        .getPublicUrl(filePath);
      uploadedIconUrl = urlData.publicUrl;
    }

    const encrypted = await encrypt(newPassword, decryptionKey);
    const { data: newPasswordData, error } = await supabase
      .from("passwords")
      .insert({
        website_url: website,
        username: username,
        encrypted_password: encrypted,
        user_id: session.user.id,
        icon_url: uploadedIconUrl,
      })
      .select()
      .single();
    if (error) {
      setError("Failed to add password.");
    } else if (newPasswordData) {
      setPasswords((prev) => [...prev, newPasswordData]);
      setWebsite("");
      setUsername("");
      setNewPassword("");
      setIconFile(null);
      if (document.getElementById("icon-file-input")) {
        document.getElementById("icon-file-input").value = "";
      }
    }
  };

  const handleIconChange = async (event, passwordId) => {
    const file = event.target.files[0];
    if (!file) return;

    const passwordEntry = passwords.find((p) => p.id === passwordId);
    const oldIconUrl = passwordEntry?.icon_url;

    const fileExt = file.name.split(".").pop();
    const fileName = `${Math.random()}.${fileExt}`;
    const filePath = `${session.user.id}/${fileName}`;

    const { error: uploadError } = await supabase.storage
      .from("entry-icons")
      .upload(filePath, file);
    if (uploadError) {
      setError("Failed to upload new icon.");
      return;
    }

    const { data: urlData } = supabase.storage
      .from("entry-icons")
      .getPublicUrl(filePath);
    const newIconUrl = urlData.publicUrl;

    setPasswords((currentPasswords) =>
      currentPasswords.map((p) =>
        p.id === passwordId ? { ...p, icon_url: newIconUrl } : p
      )
    );

    const { error: updateError } = await supabase
      .from("passwords")
      .update({ icon_url: newIconUrl })
      .eq("id", passwordId);

    if (updateError) {
      setError("Failed to update icon URL.");
      setPasswords((currentPasswords) =>
        currentPasswords.map((p) =>
          p.id === passwordId ? { ...p, icon_url: oldIconUrl } : p
        )
      );
      return;
    }

    if (oldIconUrl) {
      const oldIconPath = oldIconUrl.split("/entry-icons/")[1];
      await supabase.storage.from("entry-icons").remove([oldIconPath]);
    }
  };

  const handleDeletePassword = async (id) => {
    const passwordEntry = passwords.find((p) => p.id === id);
    const iconUrl = passwordEntry?.icon_url;

    const { error } = await supabase.from("passwords").delete().match({ id });
    if (error) {
      setError("Failed to delete password.");
      return;
    }

    if (iconUrl) {
      const iconPath = iconUrl.split("/entry-icons/")[1];
      await supabase.storage.from("entry-icons").remove([iconPath]);
    }

    setPasswords((prev) => prev.filter((p) => p.id !== id));
    setConfirmingDeleteId(null);
  };

  const handleEditClick = async (password) => {
    if (isMfaEnabled) {
      setPasswordToVerify({ ...password, intent: "edit" });
      setIsMfaModalOpen(true);
    } else {
      const decrypted = await decrypt(
        password.encrypted_password,
        decryptionKey
      );
      if (decrypted) {
        setEditingPasswordId(password.id);
        setEditingData({ username: password.username, password: decrypted });
      } else {
        setError("Decryption failed. Cannot edit entry.");
      }
    }
  };

  const handleUpdatePassword = async (e) => {
    e.preventDefault();
    const encrypted = await encrypt(editingData.password, decryptionKey);

    const { error } = await supabase
      .from("passwords")
      .update({
        username: editingData.username,
        encrypted_password: encrypted,
      })
      .eq("id", editingPasswordId);

    if (error) {
      setError("Failed to update password.");
    } else {
      setEditingPasswordId(null);
      getPasswords(); // Refresh passwords from DB
    }
  };

  const revealPassword = async (id, encryptedPass) => {
    if (isMfaEnabled) {
      if (revealedPassword[id]) {
        setRevealedPassword((prev) => ({ ...prev, [id]: null }));
      } else {
        setPasswordToVerify({
          id,
          encrypted_password: encryptedPass,
          intent: "reveal",
        });
        setIsMfaModalOpen(true);
      }
    } else {
      if (revealedPassword[id]) {
        setRevealedPassword((prev) => ({ ...prev, [id]: null }));
        return;
      }
      const decrypted = await decrypt(encryptedPass, decryptionKey);
      if (decrypted) {
        setRevealedPassword((prev) => ({ ...prev, [id]: decrypted }));
      } else {
        setError("Decryption failed. Key file may be incorrect.");
      }
    }
  };

  const handleMfaVerification = async (totp) => {
    const { data: factors, error: listError } =
      await supabase.auth.mfa.listFactors();

    if (listError) {
      console.error("Error fetching factors:", listError);
      return "Could not fetch MFA factors.";
    }

    const totpFactor = factors.totp?.find((f) => f.status === "verified");
    if (!totpFactor) {
      console.error("No verified TOTP factor found");
      return "No verified MFA method found.";
    }

    const { error } = await supabase.auth.mfa.challengeAndVerify({
      factorId: totpFactor.id,
      code: totp,
    });

    if (error) {
      console.error("MFA Verification Error:", error.message);
      return "Enter valid code";
    }

    if (!passwordToVerify) {
      return "An internal error occurred. Please try again.";
    }

    const { id, encrypted_password, intent } = passwordToVerify;
    const decrypted = await decrypt(encrypted_password, decryptionKey);

    if (decrypted) {
      if (intent === "reveal") {
        setRevealedPassword((prev) => ({ ...prev, [id]: decrypted }));
      } else if (intent === "edit") {
        setEditingPasswordId(id);
        setEditingData({
          username: passwordToVerify.username,
          password: decrypted,
        });
      }
      setIsMfaModalOpen(false);
      setPasswordToVerify(null);
      setError(null);
      return true;
    } else {
      const failMsg =
        intent === "edit"
          ? "Decryption failed. Cannot edit entry."
          : "Decryption failed after verification.";
      console.error(failMsg);
      return failMsg;
    }
  };

  const handleGeneratePassword = () => {
    setNewPassword(generateSecurePassword());
  };

  const handleCopyToClipboard = (text, id) => {
    navigator.clipboard
      .writeText(text)
      .then(() => {
        if (copiedInfo.timer) clearTimeout(copiedInfo.timer);
        const timer = setTimeout(
          () => setCopiedInfo({ id: null, timer: null }),
          2000
        );
        setCopiedInfo({ id, timer });
      })
      .catch((err) => console.error("Could not copy text: ", err));
  };

  if (!decryptionKey) {
    if (loadingPasswords)
      return (
        <div className="text-center p-8">
          <p>Checking vault status...</p>
        </div>
      );
    if (passwords.length === 0) {
      return (
        <div className="flex flex-col gap-4 text-center items-center animate-fade-in p-4">
          <h2 className="text-2xl sm:text-3xl font-bold">
            Secure Your New Vault
          </h2>
          <p className="text-slate-400 max-w-md">
            To begin, generate a unique key file. This is your only way to
            access your encrypted data.
          </p>
          <div className="bg-yellow-900/50 border border-yellow-400/30 text-yellow-200 p-4 my-4 text-left rounded-lg">
            <p className="font-bold">CRITICAL INFORMATION:</p>
            <ul className="list-disc list-inside mt-2 text-sm space-y-1">
              <li>
                Store this file in a secure, offline location (e.g., a USB
                drive).
              </li>
              <li>If you lose this file, your data is PERMANENTLY lost.</li>
            </ul>
          </div>
          <button
            onClick={handleGenerateKeyfile}
            className="bg-green-600 hover:bg-green-700 text-white font-bold py-3 px-6 rounded-lg transition-all duration-300 transform hover:scale-105 active:scale-100"
          >
            {" "}
            Generate & Download Key File{" "}
          </button>
        </div>
      );
    }
    return (
      <div className="flex flex-col gap-6 text-center animate-fade-in p-4">
        <h2 className="text-2xl sm:text-3xl font-bold">Vault Locked</h2>
        <p className="text-slate-400 mb-4">
          Please upload your key file to decrypt your vault.
        </p>
        <div>
          <label
            htmlFor="key-file-upload"
            className="bg-violet-600 hover:bg-violet-700 cursor-pointer text-white font-bold py-3 px-8 rounded-lg transition-all duration-300 inline-flex items-center gap-2 transform hover:scale-105 active:scale-100"
          >
            <i className="fa-solid fa-upload w-5 h-5"></i>
            <span>Upload Key File</span>
          </label>
          <input
            id="key-file-upload"
            type="file"
            className="hidden"
            accept=".txt"
            onChange={handleFileUnlock}
          />
        </div>
        {error && <p className="text-red-400 mt-2">{error}</p>}
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-8 animate-fade-in">
      {isMfaModalOpen && (
        <MfaVerifyModal
          onVerify={handleMfaVerification}
          onClose={() => setIsMfaModalOpen(false)}
        />
      )}
      <header className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-2">
        <h1 className="text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-violet-400 to-purple-500">
          My Vault
        </h1>
        <div className="flex items-center gap-4">
          <button
            onClick={() => setShowMfaSetup(!showMfaSetup)}
            className="bg-slate-700/50 hover:bg-slate-700 text-white font-bold py-2 px-4 rounded-lg transition-all text-sm"
          >
            {showMfaSetup ? "Close Settings" : "MFA Settings"}
          </button>
          <button
            onClick={() => supabase.auth.signOut()}
            className="bg-red-600/80 hover:bg-red-600 text-white font-bold py-2 px-4 rounded-lg transition-all text-sm"
          >
            {" "}
            Sign Out{" "}
          </button>
        </div>
      </header>

      {showMfaSetup ? (
        <MfaSetup isEnabled={isMfaEnabled} onStatusChange={getProfile} />
      ) : (
        <>
          <section className="bg-black/20 p-4 sm:p-6 rounded-lg border border-white/10">
            <h2 className="text-xl font-semibold mb-4">Add New Credential</h2>
            <form
              onSubmit={handleAddPassword}
              className="grid grid-cols-1 md:grid-cols-2 gap-4"
            >
              <input
                value={website}
                onChange={(e) => setWebsite(e.target.value)}
                placeholder="Website URL (e.g., google.com)"
                className="bg-slate-800/60 px-3 py-2 rounded-lg border border-white/10 focus:outline-none focus:ring-2 focus:ring-violet-500 transition-all"
              />
              <input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Username or Email"
                className="bg-slate-800/60 px-3 py-2 rounded-lg border border-white/10 focus:outline-none focus:ring-2 focus:ring-violet-500 transition-all"
              />
              <div className="relative md:col-span-2">
                <input
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  type="text"
                  placeholder="Password"
                  className="bg-slate-800/60 w-full pr-10 px-3 py-2 rounded-lg border border-white/10 focus:outline-none focus:ring-2 focus:ring-violet-500 transition-all"
                />
                <button
                  type="button"
                  onClick={handleGeneratePassword}
                  title="Generate Secure Password"
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-violet-400 transition-colors"
                >
                  <i className="fa-solid fa-wand-magic-sparkles w-5 h-5"></i>
                </button>
              </div>
              <div className="md:col-span-2">
                <label
                  htmlFor="icon-file-input"
                  className="text-sm text-slate-400"
                >
                  Custom Icon (optional)
                </label>
                <input
                  id="icon-file-input"
                  type="file"
                  onChange={(e) => setIconFile(e.target.files[0])}
                  accept="image/png, image/jpeg, image/webp"
                  className="mt-1 block w-full text-sm text-slate-400 file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-sm file:font-semibold file:bg-violet-500/20 file:text-violet-300 hover:file:bg-violet-500/30"
                />
              </div>
              <button
                type="submit"
                className="bg-green-600 hover:bg-green-700 font-bold py-2 px-4 rounded-lg transition-all md:col-span-2 transform hover:scale-[1.02] active:scale-100"
              >
                Add Credential
              </button>
            </form>
            {error && <p className="text-red-400 mt-4 text-center">{error}</p>}
          </section>

          <section className="flex flex-col gap-4">
            <div className="relative">
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search vault..."
                className="bg-slate-800/60 w-full pl-10 pr-4 py-2 rounded-lg border border-white/10 focus:outline-none focus:ring-2 focus:ring-violet-500 transition-all"
              />
              <i className="fa-solid fa-search absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"></i>
            </div>

            {loadingPasswords && (
              <p className="text-center text-slate-400">
                Loading credentials...
              </p>
            )}
            {!filteredPasswords.length && !loadingPasswords && (
              <p className="text-center text-slate-400 p-4">
                {passwords.length > 0
                  ? "No results found."
                  : "Your vault is empty."}
              </p>
            )}

            {filteredPasswords.map((p) => (
              <div
                key={p.id}
                className="bg-black/20 p-4 rounded-lg border border-white/10 "
              >
                {editingPasswordId === p.id ? (
                  <form
                    onSubmit={handleUpdatePassword}
                    className="flex flex-col gap-4"
                  >
                    <div className="flex items-center gap-4">
                      <img
                        src={
                          p.icon_url ||
                          `https://www.google.com/s2/favicons?sz=64&domain_url=${p.website_url}`
                        }
                        alt="site icon"
                        className="w-10 h-10 rounded-full bg-slate-700 object-contain p-1 flex-shrink-0"
                      />
                      <div className="flex-grow">
                        <p className="font-bold text-lg text-violet-300 break-words">
                          {p.website_url}
                        </p>
                        <input
                          type="text"
                          value={editingData.username}
                          onChange={(e) =>
                            setEditingData({
                              ...editingData,
                              username: e.target.value,
                            })
                          }
                          className="bg-slate-800/60 w-full px-2 py-1 rounded-md border border-white/10"
                        />
                      </div>
                    </div>
                    <input
                      type="text"
                      value={editingData.password}
                      onChange={(e) =>
                        setEditingData({
                          ...editingData,
                          password: e.target.value,
                        })
                      }
                      className="bg-slate-800/60 w-full px-2 py-1 rounded-md border border-white/10 font-mono"
                    />
                    <div className="flex items-center justify-end gap-2">
                      <button
                        type="button"
                        onClick={() => setEditingPasswordId(null)}
                        className="bg-slate-600/50 hover:bg-slate-600 text-white font-bold py-1 px-4 rounded-lg transition-all text-sm"
                      >
                        Cancel
                      </button>
                      <button
                        type="submit"
                        className="bg-green-600 hover:bg-green-700 text-white font-bold py-1 px-4 rounded-lg transition-all text-sm"
                      >
                        Save
                      </button>
                    </div>
                  </form>
                ) : (
                  <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                    <div className="flex items-center gap-4 flex-grow">
                      <div className="relative group flex-shrink-0">
                        <img
                          src={
                            p.icon_url ||
                            `https://www.google.com/s2/favicons?sz=64&domain_url=${p.website_url}`
                          }
                          alt="site icon"
                          className="w-10 h-10 rounded-full bg-slate-700 object-contain p-1"
                          onError={(e) => {
                            e.target.onerror = null;
                            e.target.src = `data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='64' height='64' viewBox='0 0 24 24' fill='none' stroke='rgb(148,163,184)' stroke-width='1.5' stroke-linecap='round' stroke-linejoin='round'%3E%3Ccircle cx='12' cy='12' r='10'%3E%3C/circle%3E%3Cpath d='M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20'%3E%3C/path%3E%3Cpath d='M2 12h20'%3E%3C/path%3E%3C/svg%3E`;
                          }}
                        />
                        <label
                          htmlFor={`icon-change-${p.id}`}
                          className="absolute inset-0 bg-black/60 rounded-full flex items-center justify-center cursor-pointer opacity-0 group-hover:opacity-100 transition-opacity"
                        >
                          <i className="fa-solid fa-camera text-white text-lg"></i>
                          <input
                            type="file"
                            id={`icon-change-${p.id}`}
                            className="hidden"
                            accept="image/png, image/jpeg, image/webp"
                            onChange={(e) => handleIconChange(e, p.id)}
                          />
                        </label>
                      </div>
                      <div className="flex-grow">
                        <p className="font-bold text-lg text-violet-300 break-words">
                          {p.website_url}
                        </p>
                        <div className="flex items-center gap-2">
                          <p className="text-slate-300 break-words">
                            {p.username}
                          </p>
                          <button
                            onClick={() =>
                              handleCopyToClipboard(p.username, `${p.id}-user`)
                            }
                            title="Copy Username"
                            className="text-slate-400 hover:text-white transition-colors"
                          >
                            {copiedInfo.id === `${p.id}-user` ? (
                              <i className="fa-solid fa-check w-4 h-4 text-green-400"></i>
                            ) : (
                              <i className="fa-solid fa-copy w-4 h-4"></i>
                            )}
                          </button>
                        </div>
                        {revealedPassword[p.id] && (
                          <div className="flex items-center gap-2 mt-2">
                            <span className="font-mono text-sm bg-slate-800 p-1 rounded break-all">
                              {revealedPassword[p.id]}
                            </span>
                            <button
                              onClick={() =>
                                handleCopyToClipboard(
                                  revealedPassword[p.id],
                                  p.id
                                )
                              }
                              title="Copy Password"
                              className="text-slate-400 hover:text-white transition-colors"
                            >
                              {copiedInfo.id === p.id ? (
                                <i className="fa-solid fa-check w-4 h-4 text-green-400"></i>
                              ) : (
                                <i className="fa-solid fa-copy w-4 h-4"></i>
                              )}
                            </button>
                          </div>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0 self-end sm:self-center">
                      <button
                        onClick={() => handleEditClick(p)}
                        title="Edit Credential"
                        className="p-2 bg-slate-700/50 hover:bg-slate-700 rounded-md transition-colors"
                      >
                        <i className="fa-solid fa-pencil w-5 h-5"></i>
                      </button>
                      <button
                        onClick={() =>
                          revealPassword(p.id, p.encrypted_password)
                        }
                        title={
                          revealedPassword[p.id]
                            ? "Hide Password"
                            : "Reveal Password"
                        }
                        className="p-2 bg-slate-700/50 hover:bg-slate-700 rounded-md transition-colors"
                      >
                        {revealedPassword[p.id] ? (
                          <i className="fa-solid fa-eye-slash w-5 h-5"></i>
                        ) : (
                          <i className="fa-solid fa-eye w-5 h-5"></i>
                        )}
                      </button>
                      {confirmingDeleteId === p.id ? (
                        <button
                          onClick={() => handleDeletePassword(p.id)}
                          className="p-2 bg-yellow-500/80 hover:bg-yellow-500 rounded-md transition-colors text-white font-bold text-xs"
                        >
                          Confirm?
                        </button>
                      ) : (
                        <button
                          onClick={() => setConfirmingDeleteId(p.id)}
                          title="Delete Credential"
                          className="p-2 bg-red-600/80 hover:bg-red-600 rounded-md transition-colors"
                        >
                          <i className="fa-solid fa-trash-can w-5 h-5"></i>
                        </button>
                      )}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </section>
        </>
      )}
    </div>
  );
}

// --- MFA Setup Component ---
function MfaSetup({ isEnabled, onStatusChange }) {
  const [qrCode, setQrCode] = React.useState(null);
  const [secret, setSecret] = React.useState("");
  const [verifyCode, setVerifyCode] = React.useState("");
  const [error, setError] = React.useState("");
  const [successMessage, setSuccessMessage] = React.useState("");
  const [enrolledFactor, setEnrolledFactor] = React.useState(null);

  const handleEnroll = async () => {
    setError("");

    const { data: factorsData, error: factorsError } =
      await supabase.auth.mfa.listFactors();
    if (factorsError) {
      console.error("Error listing MFA factors:", factorsError);
      setError(factorsError.message);
      return;
    }

    const unverifiedTotpFactor = factorsData?.all?.find(
      (f) => f.factor_type === "totp" && f.status === "unverified"
    );

    if (unverifiedTotpFactor) {
      const { error: unenrollError } = await supabase.auth.mfa.unenroll({
        factorId: unverifiedTotpFactor.id,
      });
      if (unenrollError) {
        setError(
          `Could not remove previous MFA attempt: ${unenrollError.message}`
        );
        return;
      }
    }

    const { data, error } = await supabase.auth.mfa.enroll({
      factorType: "totp",
    });
    if (error) {
      setError(error.message);
      return;
    }
    setEnrolledFactor(data);
    setQrCode(data.totp.qr_code);
    setSecret(data.totp.secret);
  };

  const handleVerify = async (e) => {
    e.preventDefault();

    const { data: challengeData, error: challengeError } =
      await supabase.auth.mfa.challenge({ factorId: enrolledFactor.id });
    if (challengeError) {
      setError(challengeError.message);
      return;
    }

    const { error: verifyError } = await supabase.auth.mfa.verify({
      factorId: enrolledFactor.id,
      challengeId: challengeData.id,
      code: verifyCode,
    });

    if (verifyError) {
      setError(verifyError.message);
    } else {
      const { error: profileError } = await supabase
        .from("profiles")
        .update({ mfa_enabled: true })
        .eq("id", (await supabase.auth.getUser()).data.user.id);
      if (profileError) {
        setError(profileError.message);
      } else {
        setSuccessMessage("MFA has been enabled successfully!");
        setError("");
        setQrCode(null);
        onStatusChange();
      }
    }
  };

  if (isEnabled) {
    return (
      <div className="text-center p-8 bg-black/20 rounded-lg">
        <p className="text-green-400">
          Multi-Factor Authentication is already enabled.
        </p>
      </div>
    );
  }

  return (
    <section className="bg-black/20 p-4 sm:p-6 rounded-lg border border-white/10 flex flex-col items-center gap-4">
      <h2 className="text-xl font-semibold">
        Enable Multi-Factor Authentication
      </h2>
      {!qrCode ? (
        <button
          onClick={handleEnroll}
          className="bg-blue-600 hover:bg-blue-700 font-bold py-2 px-4 rounded-lg transition-all"
        >
          Start MFA Setup
        </button>
      ) : (
        <div className="flex flex-col items-center gap-4 text-center">
          <p>
            1. Scan this QR code with your authenticator app (e.g., Google
            Authenticator, Authy).
          </p>
          <div
            className="bg-white p-4 rounded-lg"
            dangerouslySetInnerHTML={{ __html: qrCode }}
          />
          <p className="text-sm">
            Or manually enter this secret: <br />
            <code className="font-mono bg-slate-700 p-1 rounded">{secret}</code>
          </p>
          <p>
            2. Enter the 6-digit code from your app to verify and complete the
            setup.
          </p>
          <form
            onSubmit={handleVerify}
            className="flex flex-col sm:flex-row items-center gap-2"
          >
            <input
              value={verifyCode}
              onChange={(e) => setVerifyCode(e.target.value)}
              type="text"
              placeholder="6-digit code"
              maxLength="6"
              className="bg-slate-800/60 px-3 py-2 rounded-lg border border-white/10 text-center"
            />
            <button
              type="submit"
              className="bg-green-600 hover:bg-green-700 font-bold py-2 px-4 rounded-lg"
            >
              Verify & Enable
            </button>
          </form>
        </div>
      )}
      {error && <p className="text-red-400">{error}</p>}
      {successMessage && <p className="text-green-400">{successMessage}</p>}
    </section>
  );
}

// --- MFA Verification Modal ---
function MfaVerifyModal({ onVerify, onClose }) {
  const [code, setCode] = React.useState("");
  const [isLoading, setIsLoading] = React.useState(false);
  // Add a local error state to the modal
  const [error, setError] = React.useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(""); // Clear previous errors on new submission
    setIsLoading(true);
    // The onVerify function will now return `true` on success or an error string on failure
    const result = await onVerify(code);

    // If the result is not `true`, it's an error message.
    if (result !== true) {
      setError(result || "Verification failed. Please try again.");
      setIsLoading(false);
      setCode(""); // Clear input on failure
    }
    // On success, the parent component handles closing the modal.
  };

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 animate-fade-in">
      <div className="bg-slate-800 p-8 rounded-lg shadow-2xl border border-white/10 max-w-sm w-full mx-4">
        <form
          onSubmit={handleSubmit}
          className="flex flex-col gap-4 items-center"
        >
          <h2 className="text-xl font-bold">Verification Required</h2>
          <p className="text-slate-400 text-center text-sm">
            Enter the code from your authenticator app to reveal this password.
          </p>
          <input
            type="text"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder="6-digit code"
            maxLength="6"
            className="bg-slate-900/60 px-3 py-2 rounded-lg border border-white/10 text-center w-40 text-2xl tracking-widest"
          />
          {/* Display the local error message here */}
          {error && (
            <p className="text-red-400 text-center text-sm -mt-2">{error}</p>
          )}
          <div className="flex gap-2 w-full">
            <button
              type="button"
              onClick={onClose}
              disabled={isLoading}
              className="bg-slate-600/50 hover:bg-slate-600 font-bold py-2 rounded-lg transition-all w-full disabled:opacity-50"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isLoading}
              className="bg-violet-600 hover:bg-violet-700 font-bold py-2 rounded-lg transition-all w-full disabled:opacity-50"
            >
              {isLoading ? "Verifying..." : "Verify"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
