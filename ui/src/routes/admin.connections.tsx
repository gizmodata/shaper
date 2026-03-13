// SPDX-License-Identifier: MPL-2.0

import { Button } from "../components/tremor/Button";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "../components/tremor/Dialog";
import { Input } from "../components/tremor/Input";
import { Label } from "../components/tremor/Label";
import { useState, useRef, useCallback } from "react";
import {
  createFileRoute,
  isRedirect,
  useNavigate,
  useRouter,
} from "@tanstack/react-router";
import { useToast } from "../hooks/useToast";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeaderCell,
  TableRoot,
  TableRow,
} from "../components/tremor/Table";
import { useQueryApi } from "../hooks/useQueryApi";
import { RiAddFill, RiTableFill } from "@remixicon/react";
import { Tooltip } from "../components/tremor/Tooltip";
import type { IConnection, ConnectionsResponse } from "../lib/types";

export const Route = createFileRoute("/admin/connections")({
  loader: async ({ context: { queryApi } }) => {
    return queryApi("connections") as Promise<ConnectionsResponse>;
  },
  component: AdminConnections,
});

function AdminConnections() {
  const data = Route.useLoaderData();
  const [showNewDialog, setShowNewDialog] = useState(false);
  const [deleteDialog, setDeleteDialog] = useState<IConnection | null>(null);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [authType, setAuthType] = useState<"basic" | "oauth">("basic");
  const [oauthStatus, setOauthStatus] = useState<string | null>(null);
  const oauthPollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const queryApi = useQueryApi();
  const navigate = useNavigate({ from: "/admin" });
  const router = useRouter();
  const { toast } = useToast();

  const handleDelete = async (conn: IConnection) => {
    try {
      await queryApi(`connections/${conn.id}`, {
        method: "DELETE",
      });
      toast({
        title: "Success",
        description: "Connection deleted successfully",
      });
      router.invalidate();
    } catch (error) {
      if (isRedirect(error)) {
        return navigate(error.options);
      }
      toast({
        title: "Error",
        description:
          error instanceof Error
            ? error.message
            : "An error occurred",
        variant: "error",
      });
    }
  };

  const handleTest = async (conn: IConnection) => {
    setTestingId(conn.id);
    try {
      const result = (await queryApi(`connections/${conn.id}/test`, {
        method: "POST",
      })) as { success: boolean };
      toast({
        title: result.success ? "Success" : "Failed",
        description: result.success
          ? "Connection successful"
          : "Connection failed",
        variant: result.success ? undefined : "error",
      });
    } catch (error) {
      if (isRedirect(error)) {
        return navigate(error.options);
      }
      toast({
        title: "Connection Failed",
        description:
          error instanceof Error
            ? error.message
            : "An error occurred",
        variant: "error",
      });
    } finally {
      setTestingId(null);
    }
  };

  const startOAuthFlow = useCallback(async (connId: string, formHost: string, formPort: number, formUseTls: boolean, formSkipVerify: boolean) => {
    setOauthStatus("Discovering OAuth server...");
    try {
      const startResult = (await queryApi(`connections/${connId}/oauth/start`, {
        method: "POST",
      })) as { oauthUrl: string; sessionUuid: string; authUrl: string };

      setOauthStatus("Waiting for login...");

      // Open the IdP login page in a new window
      const authWindow = window.open(startResult.authUrl, "gizmosql-oauth", "width=600,height=700");

      // Poll for token completion
      let attempts = 0;
      const maxAttempts = 120; // 2 minutes

      if (oauthPollRef.current) {
        clearInterval(oauthPollRef.current);
      }

      oauthPollRef.current = setInterval(async () => {
        attempts++;
        if (attempts > maxAttempts) {
          if (oauthPollRef.current) clearInterval(oauthPollRef.current);
          oauthPollRef.current = null;
          setOauthStatus(null);
          toast({
            title: "OAuth Timeout",
            description: "Authentication timed out. Please try again.",
            variant: "error",
          });
          return;
        }

        try {
          const completeResult = (await queryApi(`connections/${connId}/oauth/complete`, {
            method: "POST",
            body: {
              oauthUrl: startResult.oauthUrl,
              sessionUuid: startResult.sessionUuid,
            },
          })) as { success: boolean };

          if (completeResult.success) {
            if (oauthPollRef.current) clearInterval(oauthPollRef.current);
            oauthPollRef.current = null;
            if (authWindow && !authWindow.closed) {
              authWindow.close();
            }
            toast({
              title: "Success",
              description: "Connection created with OAuth authentication.",
            });
            // Use setTimeout to ensure React processes state updates cleanly
            setTimeout(() => {
              setOauthStatus(null);
              setShowNewDialog(false);
              setAuthType("basic");
              router.invalidate();
            }, 100);
          }
        } catch {
          // Token not ready yet — keep polling
        }
      }, 1000);
    } catch (error) {
      setOauthStatus(null);
      if (isRedirect(error)) {
        return navigate(error.options);
      }
      toast({
        title: "OAuth Failed",
        description:
          error instanceof Error
            ? error.message
            : "Server does not support OAuth or is not reachable.",
        variant: "error",
      });
    }
  }, [queryApi, toast, router, navigate]);

  const handleCreate = async (formData: FormData) => {
    const name = formData.get("name") as string;
    const host = formData.get("host") as string;
    const port = parseInt(formData.get("port") as string, 10);
    const useTls = formData.get("useTls") === "on";
    const skipVerify = formData.get("skipVerify") === "on";

    try {
      const { id } = (await queryApi("connections", {
        method: "POST",
        body: {
          name,
          host,
          port,
          username: authType === "basic" ? (formData.get("username") as string) : "",
          password: authType === "basic" ? (formData.get("password") as string) : "",
          useTls,
          skipVerify,
        },
      })) as { id: string };

      if (authType === "oauth") {
        // Start OAuth flow for the newly created connection
        await startOAuthFlow(id, host, port, useTls, skipVerify);
      } else {
        toast({
          title: "Success",
          description: "Connection created successfully",
        });
        setShowNewDialog(false);
        router.invalidate();
      }
    } catch (error) {
      if (isRedirect(error)) {
        return navigate(error.options);
      }
      toast({
        title: "Error",
        description:
          error instanceof Error
            ? error.message
            : "An error occurred",
        variant: "error",
      });
    }
  };

  return (
    <div>
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-xl font-semibold mb-4">
          Connections
        </h2>
        <Button onClick={() => setShowNewDialog(true)}>
          <RiAddFill
            className="-ml-1 mr-0.5 size-4 shrink-0"
            aria-hidden={true}
          />
          New
        </Button>
      </div>

      {!data ? (
        <p>Loading connections...</p>
      ) : data.connections.length === 0 ? (
        <div className="mt-4 flex flex-col h-44 items-center justify-center rounded-sm p-4 text-center">
          <RiTableFill
            className="text-ctext2 dark:text-dtext2 mx-auto h-7 w-7"
            aria-hidden={true}
          />
          <p className="mt-2 text-ctext2 dark:text-dtext2 font-medium">
            No connections configured
          </p>
          <p className="mt-1 text-sm text-ctext2 dark:text-dtext2">
            Add a GizmoSQL (Arrow Flight SQL) connection to query remote data sources.
          </p>
        </div>
      ) : (
        <TableRoot>
          <Table>
            <TableHead>
              <TableRow>
                <TableHeaderCell className="text-md text-ctext dark:text-dtext">Name</TableHeaderCell>
                <TableHeaderCell className="text-md text-ctext dark:text-dtext hidden md:table-cell">Host</TableHeaderCell>
                <TableHeaderCell className="text-md text-ctext dark:text-dtext hidden md:table-cell">Status</TableHeaderCell>
                <TableHeaderCell className="text-md text-ctext dark:text-dtext hidden md:table-cell">Created</TableHeaderCell>
                <TableHeaderCell>Actions</TableHeaderCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {data.connections.map((conn) => (
                <TableRow key={conn.id}>
                  <TableCell className="font-medium text-ctext dark:text-dtext">
                    {conn.name}
                  </TableCell>
                  <TableCell className="font-medium text-ctext dark:text-dtext hidden md:table-cell">
                    {conn.host}:{conn.port}
                  </TableCell>
                  <TableCell className="hidden md:table-cell">
                    <span
                      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${
                        conn.status === "active"
                          ? "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400"
                          : "bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-400"
                      }`}
                    >
                      {conn.status}
                    </span>
                  </TableCell>
                  <TableCell className="font-medium text-ctext dark:text-dtext hidden md:table-cell">
                    <Tooltip
                      showArrow={false}
                      content={new Date(conn.createdAt).toLocaleString()}
                    >
                      {new Date(conn.createdAt).toLocaleDateString()}
                    </Tooltip>
                  </TableCell>
                  <TableCell>
                    <div className="flex gap-3">
                      <button
                        className="text-blue-600 dark:text-blue-400 hover:underline disabled:opacity-50"
                        onClick={() => handleTest(conn)}
                        disabled={testingId === conn.id}
                      >
                        {testingId === conn.id ? "Testing..." : "Test"}
                      </button>
                      <button
                        className="text-cerr dark:text-derr hover:text-cerra dark:hover:text-derra hover:underline"
                        onClick={() => setDeleteDialog(conn)}
                      >
                        Delete
                      </button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableRoot>
      )}

      <Dialog open={deleteDialog !== null} onOpenChange={(open) => !open && setDeleteDialog(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Confirm Deletion</DialogTitle>
            <DialogDescription>
              {deleteDialog && `Are you sure you want to delete the connection "${deleteDialog.name}"? Dashboards using this connection will fall back to local DuckDB.`}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button onClick={() => setDeleteDialog(null)} variant="secondary">Cancel</Button>
            <Button
              variant="destructive"
              onClick={() => {
                if (deleteDialog) {
                  handleDelete(deleteDialog);
                  setDeleteDialog(null);
                }
              }}
            >
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog
        open={showNewDialog}
        onOpenChange={(open) => {
          if (!open && oauthPollRef.current) {
            clearInterval(oauthPollRef.current);
            oauthPollRef.current = null;
            setOauthStatus(null);
          }
          setShowNewDialog(open);
          if (!open) setAuthType("basic");
        }}
      >
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>New Connection</DialogTitle>
            <DialogDescription>
              Connect to a GizmoSQL (Arrow Flight SQL) server
            </DialogDescription>
          </DialogHeader>

          <form
            className="space-y-4 mt-4"
            onSubmit={(e) => {
              e.preventDefault();
              handleCreate(new FormData(e.currentTarget));
            }}
          >
            <div>
              <Label htmlFor="name">Name</Label>
              <Input
                id="name"
                name="name"
                placeholder="My GizmoSQL Server"
                required
                autoFocus
              />
            </div>
            <div className="grid grid-cols-3 gap-2">
              <div className="col-span-2">
                <Label htmlFor="host">Host</Label>
                <Input
                  id="host"
                  name="host"
                  placeholder="localhost"
                  required
                />
              </div>
              <div>
                <Label htmlFor="port">Port</Label>
                <Input
                  id="port"
                  name="port"
                  type="number"
                  placeholder="31337"
                  defaultValue={31337}
                  required
                />
              </div>
            </div>

            <div>
              <Label>Authentication</Label>
              <div className="flex gap-4 mt-1">
                <label className="flex items-center gap-2 text-sm text-ctext dark:text-dtext cursor-pointer">
                  <input
                    type="radio"
                    name="authType"
                    value="basic"
                    checked={authType === "basic"}
                    onChange={() => setAuthType("basic")}
                  />
                  Username / Password
                </label>
                <label className="flex items-center gap-2 text-sm text-ctext dark:text-dtext cursor-pointer">
                  <input
                    type="radio"
                    name="authType"
                    value="oauth"
                    checked={authType === "oauth"}
                    onChange={() => setAuthType("oauth")}
                  />
                  OAuth / SSO
                </label>
              </div>
            </div>

            {authType === "basic" && (
              <>
                <div>
                  <Label htmlFor="username">Username</Label>
                  <Input
                    id="username"
                    name="username"
                    placeholder="admin"
                  />
                </div>
                <div>
                  <Label htmlFor="password">Password</Label>
                  <Input
                    id="password"
                    name="password"
                    type="password"
                    placeholder="Password"
                  />
                </div>
              </>
            )}

            {authType === "oauth" && (
              <p className="text-sm text-ctext2 dark:text-dtext2">
                After creating the connection, a login window will open for you to authenticate with your identity provider.
              </p>
            )}

            <div className="flex gap-6">
              <label className="flex items-center gap-2 text-sm text-ctext dark:text-dtext">
                <input type="checkbox" name="useTls" className="rounded" />
                Use TLS
              </label>
              <label className="flex items-center gap-2 text-sm text-ctext dark:text-dtext">
                <input type="checkbox" name="skipVerify" className="rounded" />
                Skip TLS Verify
              </label>
            </div>

            {oauthStatus && (
              <p className="text-sm text-blue-600 dark:text-blue-400 animate-pulse">
                {oauthStatus}
              </p>
            )}

            <DialogFooter>
              <DialogClose asChild>
                <Button type="button" variant="secondary">Cancel</Button>
              </DialogClose>
              <Button type="submit" className="mb-4 sm:mb-0" disabled={!!oauthStatus}>
                {oauthStatus ? oauthStatus : authType === "oauth" ? "Create & Authenticate" : "Create"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
