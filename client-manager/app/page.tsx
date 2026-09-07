"use client";

import { useEffect, useState } from "react";
import { ClientConfig, AVAILABLE_SCOPES } from "@/lib/types";
import {
  ShieldCheck,
  Plus,
  RefreshCw,
  Trash2,
  Edit,
  Eye,
  Key,
  CheckCircle2,
  AlertCircle,
  Download,
  HardDrive,
  Radio,
  Lock,
} from "lucide-react";

export default function Home() {
  const [clients, setClients] = useState<ClientConfig[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [syncStatus, setSyncStatus] = useState<string | null>(null);

  // Modal states
  const [modalMode, setModalMode] = useState<"create" | "edit" | "view" | null>(null);
  const [selectedClient, setSelectedClient] = useState<ClientConfig | null>(null);

  // Form states
  const [formData, setFormData] = useState({
    clientId: "",
    clientName: "",
    redirectUrisText: "http://localhost:8080/callback",
    postLogoutRedirectUrisText: "http://localhost:8080/",
    scopes: ["openid", "profile", "email", "user.read"],
    customScope: "",
    publicKeyPem: "",
    accessTokenTtl: 15,
    refreshTokenTtl: 30,
    requireProofKey: true,
  });

  const [generatedKeyNotice, setGeneratedKeyNotice] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    fetchClients();
  }, []);

  async function fetchClients() {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/clients");
      if (!res.ok) throw new Error(`HTTP ${res.status}: Failed to fetch clients`);
      const data = await res.json();
      setClients(data);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  function openCreateModal() {
    setFormData({
      clientId: `client-${Math.random().toString(36).substring(2, 8)}`,
      clientName: "",
      redirectUrisText: "http://localhost:8080/callback",
      postLogoutRedirectUrisText: "http://localhost:8080/",
      scopes: ["openid", "profile", "email", "user.read"],
      customScope: "",
      publicKeyPem: "",
      accessTokenTtl: 15,
      refreshTokenTtl: 30,
      requireProofKey: true,
    });
    setGeneratedKeyNotice(null);
    setModalMode("create");
  }

  function openEditModal(client: ClientConfig) {
    setSelectedClient(client);
    setFormData({
      clientId: client.clientId,
      clientName: client.clientName || "",
      redirectUrisText: (client.redirectUris || []).join("\n"),
      postLogoutRedirectUrisText: (client.postLogoutRedirectUris || []).join("\n"),
      scopes: client.scopes || [],
      customScope: "",
      publicKeyPem: client.publicKeyPem || "",
      accessTokenTtl: client.accessTokenTimeToLiveMinutes || 15,
      refreshTokenTtl: client.refreshTokenTimeToLiveDays || 30,
      requireProofKey: client.requireProofKey ?? true,
    });
    setGeneratedKeyNotice(null);
    setModalMode("edit");
  }

  function openViewModal(client: ClientConfig) {
    setSelectedClient(client);
    setModalMode("view");
  }

  function toggleScope(scopeId: string) {
    setFormData((prev) => ({
      ...prev,
      scopes: prev.scopes.includes(scopeId)
        ? prev.scopes.filter((s) => s !== scopeId)
        : [...prev.scopes, scopeId],
    }));
  }

  function addCustomScope() {
    const s = formData.customScope.trim();
    if (s && !formData.scopes.includes(s)) {
      setFormData((prev) => ({
        ...prev,
        scopes: [...prev.scopes, s],
        customScope: "",
      }));
    }
  }

  function handleFileUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      if (content) {
        setFormData((prev) => ({ ...prev, publicKeyPem: content.trim() }));
      }
    };
    reader.readAsText(file);
  }

  // Browser-based RSA Key Pair Generation
  async function generateRsaKeyPair() {
    try {
      setGeneratedKeyNotice("Generating 2048-bit RSA key pair in browser...");
      const keyPair = await window.crypto.subtle.generateKey(
        {
          name: "RSASSA-PKCS1-v1_5",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        },
        true,
        ["sign", "verify"]
      );

      // Export Public Key (SPKI)
      const spki = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
      const publicBase64 = btoa(String.fromCharCode(...new Uint8Array(spki)));
      const publicPem = `-----BEGIN PUBLIC KEY-----\n${publicBase64.match(/.{1,64}/g)?.join("\n")}\n-----END PUBLIC KEY-----`;

      // Export Private Key (PKCS#8)
      const pkcs8 = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
      const privateBase64 = btoa(String.fromCharCode(...new Uint8Array(pkcs8)));
      const privatePem = `-----BEGIN PRIVATE KEY-----\n${privateBase64.match(/.{1,64}/g)?.join("\n")}\n-----END PRIVATE KEY-----`;

      setFormData((prev) => ({ ...prev, publicKeyPem: publicPem }));

      // Trigger automatic download of private key
      const blob = new Blob([privatePem], { type: "application/x-pem-file" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${formData.clientId || "client"}_private_key.pem`;
      a.click();
      URL.revokeObjectURL(url);

      setGeneratedKeyNotice("Generated RSA key pair! Private key downloaded to your browser. Public key populated below.");
    } catch (err) {
      alert(`Key generation error: ${(err as Error).message}`);
      setGeneratedKeyNotice(null);
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!formData.clientId.trim()) {
      alert("Client ID is required");
      return;
    }
    if (!formData.publicKeyPem.includes("BEGIN PUBLIC KEY")) {
      alert("A valid RSA Public Key (PEM format) is required");
      return;
    }

    setSubmitting(true);
    try {
      const payload = {
        clientId: formData.clientId.trim(),
        clientName: formData.clientName.trim() || formData.clientId.trim(),
        redirectUris: formData.redirectUrisText
          .split("\n")
          .map((u) => u.trim())
          .filter(Boolean),
        postLogoutRedirectUris: formData.postLogoutRedirectUrisText
          .split("\n")
          .map((u) => u.trim())
          .filter(Boolean),
        scopes: formData.scopes,
        publicKeyPem: formData.publicKeyPem.trim(),
        requireProofKey: formData.requireProofKey,
        accessTokenTimeToLiveMinutes: Number(formData.accessTokenTtl) || 15,
        refreshTokenTimeToLiveDays: Number(formData.refreshTokenTtl) || 30,
      };

      const url = modalMode === "edit" ? `/api/clients/${formData.clientId}` : "/api/clients";
      const method = modalMode === "edit" ? "PUT" : "POST";

      const res = await fetch(url, {
        method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const errJson = await res.json();
        throw new Error(errJson.error || "Failed to save client");
      }

      setSyncStatus(`Client '${payload.clientId}' successfully saved to PostgreSQL via Spring Admin API!`);
      setTimeout(() => setSyncStatus(null), 5000);
      setModalMode(null);
      await fetchClients();
    } catch (err) {
      alert((err as Error).message);
    } finally {
      setSubmitting(false);
    }
  }

  async function handleDelete(client: ClientConfig) {
    if (!confirm(`Are you sure you want to delete client '${client.clientId}'? This will remove it from PostgreSQL and revoke its ability to authenticate.`)) {
      return;
    }

    try {
      const res = await fetch(`/api/clients/${client.clientId}`, { method: "DELETE" });
      if (!res.ok) throw new Error("Failed to delete client");
      setSyncStatus(`Client '${client.clientId}' deleted from PostgreSQL & Spring near-cache purged.`);
      setTimeout(() => setSyncStatus(null), 5000);
      await fetchClients();
    } catch (err) {
      alert((err as Error).message);
    }
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* Header */}
      <header className="border-b border-slate-800 pb-6 mb-8 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-indigo-600/20 text-indigo-400 border border-indigo-500/30">
              <ShieldCheck className="w-8 h-8" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
                OAuth 2.1 Client Config Manager
                <span className="text-xs px-2.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 font-medium">
                  PostgreSQL Backed
                </span>
              </h1>
              <p className="text-sm text-slate-400 mt-0.5">
                Centralized management for OAuth 2.1 clients via Spring Admin API with PostgreSQL persistence and cluster near-caching.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchClients}
            disabled={loading}
            className="inline-flex items-center gap-2 px-3.5 py-2 text-sm font-medium rounded-lg bg-slate-800 text-slate-200 hover:bg-slate-700 border border-slate-700 transition"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
          <button
            onClick={openCreateModal}
            className="inline-flex items-center gap-2 px-4 py-2 text-sm font-semibold rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white shadow-lg shadow-indigo-600/20 transition"
          >
            <Plus className="w-4 h-4" />
            Register New Client
          </button>
        </div>
      </header>

      {/* Sync Status Banner */}
      {syncStatus && (
        <div className="mb-6 p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 flex items-center gap-3 text-sm animate-fade-in">
          <CheckCircle2 className="w-5 h-5 flex-shrink-0 text-emerald-400" />
          <span>{syncStatus}</span>
        </div>
      )}

      {/* Architecture Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="flex items-center gap-3 mb-2">
            <HardDrive className="w-5 h-5 text-sky-400" />
            <h3 className="font-semibold text-slate-200 text-sm">Persistence Tier</h3>
          </div>
          <p className="text-xs text-slate-400">
            PostgreSQL relational store (<code className="text-sky-400 bg-slate-950 px-1.5 py-0.5 rounded">oauth2_registered_client</code>) managed strictly by Spring.
          </p>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="flex items-center gap-3 mb-2">
            <Radio className="w-5 h-5 text-indigo-400" />
            <h3 className="font-semibold text-slate-200 text-sm">L1 Near-Cache & Sync</h3>
          </div>
          <p className="text-xs text-slate-400">
            Microsecond reads via Spring JVM near-cache; Redis Pub/Sub invalidates nodes in &lt; 1 ms.
          </p>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="flex items-center gap-3 mb-2">
            <Lock className="w-5 h-5 text-amber-400" />
            <h3 className="font-semibold text-slate-200 text-sm">Strict Security</h3>
          </div>
          <p className="text-xs text-slate-400">
            Enforces <code className="text-amber-400 bg-slate-950 px-1.5 py-0.5 rounded">private_key_jwt</code> (RFC 7523), PKCE S256, and server-determined scopes.
          </p>
        </div>
      </div>

      {/* Client Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
        <div className="p-5 border-b border-slate-800 flex items-center justify-between">
          <h2 className="text-base font-semibold text-white">Registered OAuth 2.1 Clients ({clients.length})</h2>
          <span className="text-xs text-slate-400">Synchronized with Spring Authorization Server</span>
        </div>

        {loading && clients.length === 0 ? (
          <div className="p-12 text-center text-slate-400 flex flex-col items-center justify-center gap-3">
            <RefreshCw className="w-8 h-8 animate-spin text-indigo-400" />
            <span>Loading clients from Spring...</span>
          </div>
        ) : error ? (
          <div className="p-8 text-center text-rose-400 flex items-center justify-center gap-2">
            <AlertCircle className="w-5 h-5" />
            <span>{error}</span>
          </div>
        ) : clients.length === 0 ? (
          <div className="p-12 text-center text-slate-400">
            <p>No clients found in PostgreSQL.</p>
            <button
              onClick={openCreateModal}
              className="mt-4 inline-flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-indigo-600 text-white"
            >
              <Plus className="w-4 h-4" /> Register First Client
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm text-slate-300">
              <thead className="bg-slate-950/50 text-xs uppercase tracking-wider text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="px-6 py-4">Client ID & Name</th>
                  <th className="px-6 py-4">Auth Method</th>
                  <th className="px-6 py-4">Server-Determined Scopes</th>
                  <th className="px-6 py-4">Redirect URIs</th>
                  <th className="px-6 py-4">Public Key</th>
                  <th className="px-6 py-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {clients.map((c) => (
                  <tr key={c.clientId} className="hover:bg-slate-800/40 transition">
                    <td className="px-6 py-4">
                      <div className="font-semibold text-white">{c.clientId}</div>
                      <div className="text-xs text-slate-400">{c.clientName || "Unnamed Client"}</div>
                    </td>
                    <td className="px-6 py-4">
                      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-amber-500/10 text-amber-400 border border-amber-500/20">
                        <Key className="w-3 h-3" />
                        private_key_jwt
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex flex-wrap gap-1 max-w-xs">
                        {(c.scopes || []).map((s) => (
                          <span
                            key={s}
                            className={`text-xs px-2 py-0.5 rounded font-mono ${
                              s === "demo.secret_access"
                                ? "bg-rose-500/20 text-rose-300 border border-rose-500/30"
                                : "bg-slate-800 text-slate-300"
                            }`}
                          >
                            {s}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="text-xs text-slate-400 max-w-xs truncate font-mono">
                        {(c.redirectUris || [])[0] || "None"}
                        {(c.redirectUris || []).length > 1 && (
                          <span className="ml-1 text-slate-500">
                            (+{(c.redirectUris || []).length - 1} more)
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      {c.publicKeyPem ? (
                        <span className="inline-flex items-center gap-1 text-xs text-emerald-400">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          RSA 2048 Loaded
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-xs text-rose-400">
                          <AlertCircle className="w-3.5 h-3.5" />
                          Missing Key
                        </span>
                      )}
                    </td>
                    <td className="px-6 py-4 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => openViewModal(c)}
                          className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white transition"
                          title="View JSON"
                        >
                          <Eye className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => openEditModal(c)}
                          className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white transition"
                          title="Edit Client"
                        >
                          <Edit className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => handleDelete(c)}
                          className="p-1.5 rounded-lg hover:bg-rose-500/20 text-slate-400 hover:text-rose-400 transition"
                          title="Delete Client"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Modal: Create or Edit Client */}
      {(modalMode === "create" || modalMode === "edit") && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto p-6 shadow-2xl">
            <div className="flex items-center justify-between pb-4 mb-6 border-b border-slate-800">
              <h2 className="text-xl font-bold text-white flex items-center gap-2">
                <Key className="w-5 h-5 text-indigo-400" />
                {modalMode === "create" ? "Register New OAuth 2.1 Client" : `Edit Client: ${formData.clientId}`}
              </h2>
              <button
                onClick={() => setModalMode(null)}
                className="text-slate-400 hover:text-white text-lg font-bold"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleSubmit} className="space-y-6">
              {/* Basic Fields */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                    Client ID *
                  </label>
                  <input
                    type="text"
                    required
                    disabled={modalMode === "edit"}
                    value={formData.clientId}
                    onChange={(e) => setFormData({ ...formData, clientId: e.target.value })}
                    className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-indigo-500 text-sm font-mono"
                    placeholder="e.g. partner-service-app"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                    Client Name
                  </label>
                  <input
                    type="text"
                    value={formData.clientName}
                    onChange={(e) => setFormData({ ...formData, clientName: e.target.value })}
                    className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-indigo-500 text-sm"
                    placeholder="e.g. Partner Portal"
                  />
                </div>
              </div>

              {/* Redirect URIs */}
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                  Redirect URIs (one per line)
                </label>
                <textarea
                  rows={2}
                  value={formData.redirectUrisText}
                  onChange={(e) => setFormData({ ...formData, redirectUrisText: e.target.value })}
                  className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-indigo-500 text-xs font-mono"
                  placeholder="http://localhost:8080/callback"
                />
              </div>

              {/* Post Logout Redirect URIs */}
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                  Post-Logout Redirect URIs (one per line)
                </label>
                <textarea
                  rows={2}
                  value={formData.postLogoutRedirectUrisText}
                  onChange={(e) => setFormData({ ...formData, postLogoutRedirectUrisText: e.target.value })}
                  className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-indigo-500 text-xs font-mono"
                  placeholder="http://localhost:8080/"
                />
              </div>

              {/* Scopes Selection */}
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
                  Server-Determined Scopes (Pre-assigned Scopes)
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mb-3">
                  {AVAILABLE_SCOPES.map((scope) => {
                    const checked = formData.scopes.includes(scope.id);
                    return (
                      <div
                        key={scope.id}
                        onClick={() => toggleScope(scope.id)}
                        className={`p-3 rounded-lg border cursor-pointer transition flex items-start gap-3 ${
                          checked
                            ? "bg-indigo-600/10 border-indigo-500 text-white"
                            : "bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700"
                        }`}
                      >
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={() => {}}
                          className="mt-0.5 text-indigo-600 rounded bg-slate-900 border-slate-700"
                        />
                        <div>
                          <div className="font-mono text-xs font-bold text-slate-200">{scope.label}</div>
                          <div className="text-[11px] text-slate-400 leading-tight mt-0.5">
                            {scope.description}
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Custom Scope input */}
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={formData.customScope}
                    onChange={(e) => setFormData({ ...formData, customScope: e.target.value })}
                    placeholder="Add custom scope (e.g. orders.write)"
                    className="flex-1 px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white"
                  />
                  <button
                    type="button"
                    onClick={addCustomScope}
                    className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200"
                  >
                    + Add Scope
                  </button>
                </div>
              </div>

              {/* Public Key Upload / Generate */}
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-semibold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
                    <Key className="w-3.5 h-3.5 text-amber-400" />
                    Client RSA Public Key (PEM format) *
                  </label>
                  <button
                    type="button"
                    onClick={generateRsaKeyPair}
                    className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-md bg-amber-500/10 text-amber-400 hover:bg-amber-500/20 border border-amber-500/30 transition"
                  >
                    <Download className="w-3.5 h-3.5" />
                    Generate Key Pair in Browser
                  </button>
                </div>

                {generatedKeyNotice && (
                  <div className="p-2.5 rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-xs text-indigo-300">
                    {generatedKeyNotice}
                  </div>
                )}

                <div className="flex items-center gap-3">
                  <label className="cursor-pointer inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 border border-slate-700">
                    Upload .pem / .pub file
                    <input
                      type="file"
                      accept=".pem,.pub,.txt"
                      onChange={handleFileUpload}
                      className="hidden"
                    />
                  </label>
                  <span className="text-xs text-slate-500">or paste PEM below</span>
                </div>

                <textarea
                  rows={6}
                  required
                  value={formData.publicKeyPem}
                  onChange={(e) => setFormData({ ...formData, publicKeyPem: e.target.value })}
                  placeholder="-----BEGIN PUBLIC KEY-----&#10;MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...&#10;-----END PUBLIC KEY-----"
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-white font-mono text-[11px] focus:outline-none focus:border-indigo-500"
                />
              </div>

              {/* Token Lifetimes & PKCE */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                    Access Token TTL (minutes)
                  </label>
                  <input
                    type="number"
                    min="1"
                    value={formData.accessTokenTtl}
                    onChange={(e) => setFormData({ ...formData, accessTokenTtl: parseInt(e.target.value) || 15 })}
                    className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white text-sm"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                    Refresh Token TTL (days)
                  </label>
                  <input
                    type="number"
                    min="1"
                    value={formData.refreshTokenTtl}
                    onChange={(e) => setFormData({ ...formData, refreshTokenTtl: parseInt(e.target.value) || 30 })}
                    className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white text-sm"
                  />
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex items-center justify-end gap-3 pt-4 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setModalMode(null)}
                  className="px-4 py-2 text-sm font-medium rounded-lg text-slate-300 hover:bg-slate-800"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-5 py-2 text-sm font-semibold rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white shadow-lg shadow-indigo-600/20 disabled:opacity-50"
                >
                  {submitting ? "Saving to PostgreSQL..." : modalMode === "create" ? "Save Client" : "Update Client"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: View Client JSON */}
      {modalMode === "view" && selectedClient && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-2xl p-6 shadow-2xl">
            <div className="flex items-center justify-between pb-4 mb-4 border-b border-slate-800">
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <Eye className="w-5 h-5 text-indigo-400" />
                Client JSON: {selectedClient.clientId}
              </h2>
              <button
                onClick={() => setModalMode(null)}
                className="text-slate-400 hover:text-white text-lg font-bold"
              >
                ✕
              </button>
            </div>

            <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-indigo-300 overflow-x-auto max-h-[60vh]">
              {JSON.stringify(selectedClient, null, 2)}
            </pre>

            <div className="flex justify-end mt-4">
              <button
                onClick={() => setModalMode(null)}
                className="px-4 py-2 text-sm font-medium rounded-lg bg-slate-800 hover:bg-slate-700 text-white"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
