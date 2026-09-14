import { listUsers, flagUserFraud, unflagUserFraud, createUser, editUser } from "../../lib/users";
import { revalidatePath } from "next/cache";
import { AlertTriangle, UserCheck, ShieldAlert, UserPlus, ChevronLeft, ChevronRight, Edit2 } from "lucide-react";
import Link from "next/link";

export default async function UsersPage(props: { searchParams: Promise<{ page?: string; edit?: string }> }) {
  const searchParams = await props.searchParams;
  const page = parseInt(searchParams.page || "1", 10);
  const editEmail = searchParams.edit;
  const data = await listUsers(page, 10);

  async function flagFraudAction(formData: FormData) {
    "use server";
    const email = formData.get("email") as string;
    await flagUserFraud(email);
    revalidatePath("/users");
  }

  async function unflagFraudAction(formData: FormData) {
    "use server";
    const email = formData.get("email") as string;
    await unflagUserFraud(email);
    revalidatePath("/users");
  }

  async function createUserAction(formData: FormData) {
    "use server";
    await createUser({
      email: String(formData.get("email") ?? ""),
      password: String(formData.get("password") ?? "")
    });
    revalidatePath("/users");
  }

  async function editUserAction(formData: FormData) {
    "use server";
    const oldEmail = formData.get("oldEmail") as string;
    await editUser(oldEmail, {
      email: formData.get("email") as string,
      password: formData.get("password") as string
    });
    revalidatePath("/users");
  }

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-bold tracking-tight text-white">Registered Users</h1>
        <p className="text-sm text-slate-400 mt-1">Manage platform users, passwords, and handle fraud interventions.</p>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="px-6 py-4 border-b border-slate-800 bg-slate-800/50 flex items-center gap-2">
          <UserPlus className="h-5 w-5 text-indigo-400" />
          <h3 className="text-base font-semibold text-white">Add New User</h3>
        </div>
        <div className="p-6">
          <form action={createUserAction} className="grid grid-cols-1 md:grid-cols-3 gap-4 items-end">
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">Email</label>
              <input type="email" name="email" required className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white text-sm focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500" />
            </div>
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">Password</label>
              <input type="password" name="password" required className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white text-sm focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500" />
            </div>
            <button type="submit" className="w-full bg-indigo-600 text-white px-4 py-2 rounded-lg font-medium hover:bg-indigo-500 shadow-lg shadow-indigo-600/20">Create User</button>
          </form>
        </div>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl flex flex-col">
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-slate-800">
            <thead className="bg-slate-800/50">
              <tr>
                <th className="py-4 pl-6 pr-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">ID</th>
                <th className="px-3 py-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">Email</th>
                <th className="px-3 py-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">Status</th>
                <th className="relative py-4 pl-3 pr-6 text-right"><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 bg-slate-900">
              {data.users.map((u) => (
                <tr key={u.id} className="hover:bg-slate-800/30 transition-colors">
                  <td className="whitespace-nowrap py-4 pl-6 pr-3 text-xs font-mono text-slate-500">{u.id.split("-")[0]}...</td>
                  <td className="whitespace-nowrap px-3 py-4 text-sm font-medium text-white">
                    {editEmail === u.email ? (
                      <form id={`edit-${u.id}`} action={editUserAction} className="flex gap-2">
                        <input type="hidden" name="oldEmail" value={u.email} />
                        <input type="email" name="email" defaultValue={u.email} className="px-2 py-1 rounded bg-slate-950 border border-slate-800 text-white text-xs" />
                        <input type="password" name="password" placeholder="New Password" className="px-2 py-1 rounded bg-slate-950 border border-slate-800 text-white text-xs w-32" />
                      </form>
                    ) : (
                      u.email
                    )}
                  </td>
                  <td className="whitespace-nowrap px-3 py-4 text-sm">
                    {u.is_fraud ? (
                      <span className="inline-flex items-center gap-1.5 rounded-full bg-red-500/10 border border-red-500/20 px-2.5 py-1 text-xs font-medium text-red-400">
                        <ShieldAlert className="h-3.5 w-3.5" /> Fraud
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/20 px-2.5 py-1 text-xs font-medium text-emerald-400">
                        <UserCheck className="h-3.5 w-3.5" /> Active
                      </span>
                    )}
                  </td>
                  <td className="relative whitespace-nowrap py-4 pl-3 pr-6 text-right text-sm font-medium">
                    <div className="flex justify-end gap-3 items-center">
                      {editEmail === u.email ? (
                        <div className="flex gap-2">
                          <button form={`edit-${u.id}`} type="submit" className="text-emerald-400 hover:text-emerald-300">Save</button>
                          <Link href="/users" className="text-slate-400 hover:text-slate-300">Cancel</Link>
                        </div>
                      ) : (
                        <Link href={`/users?edit=${encodeURIComponent(u.email)}`} className="text-indigo-400 hover:text-indigo-300 flex items-center gap-1">
                          <Edit2 className="h-4 w-4" /> Edit
                        </Link>
                      )}

                      {!u.is_fraud ? (
                        <form action={flagFraudAction}>
                          <input type="hidden" name="email" value={u.email} />
                          <button type="submit" className="inline-flex items-center gap-1.5 text-red-400 hover:text-red-300">
                            <AlertTriangle className="h-4 w-4" /> Flag Fraud
                          </button>
                        </form>
                      ) : (
                        <form action={unflagFraudAction}>
                          <input type="hidden" name="email" value={u.email} />
                          <button type="submit" className="inline-flex items-center gap-1.5 text-emerald-400 hover:text-emerald-300">
                            <UserCheck className="h-4 w-4" /> Unflag
                          </button>
                        </form>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
              {data.users.length === 0 && (
                <tr><td colSpan={4} className="py-8 text-center text-sm text-slate-500">No users found.</td></tr>
              )}
            </tbody>
          </table>
        </div>
        
        {/* Pagination Controls */}
        <div className="px-6 py-4 border-t border-slate-800 bg-slate-800/30 flex items-center justify-between">
          <div className="text-sm text-slate-400">
            Showing page <span className="font-semibold text-white">{data.page}</span> of <span className="font-semibold text-white">{Math.max(1, data.totalPages)}</span> ({data.total} total users)
          </div>
          <div className="flex gap-2">
            {data.page > 1 ? (
              <Link href={`/users?page=${data.page - 1}`} aria-label="Go to previous page" className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors">
                <ChevronLeft className="h-5 w-5" />
              </Link>
            ) : (
              <button type="button" disabled aria-label="Previous page (unavailable)" className="p-2 rounded-lg bg-slate-800/50 text-slate-600 cursor-not-allowed">
                <ChevronLeft className="h-5 w-5" />
              </button>
            )}
            
            {data.page < data.totalPages ? (
              <Link href={`/users?page=${data.page + 1}`} aria-label="Go to next page" className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors">
                <ChevronRight className="h-5 w-5" />
              </Link>
            ) : (
              <button type="button" disabled aria-label="Next page (unavailable)" className="p-2 rounded-lg bg-slate-800/50 text-slate-600 cursor-not-allowed">
                <ChevronRight className="h-5 w-5" />
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
