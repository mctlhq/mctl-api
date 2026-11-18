# Helm chart extension slots

The chart (`helm/`) exposes five optional slots so a deployment can add a
co-located container without forking the template. All are empty by default
and an empty value renders nothing: the default render is pinned byte for byte
by `helm/testdata/default-deployment.golden.yaml`
(`TestDefaultDeploymentMatchesGolden`).

| Value | Renders into | Notes |
| --- | --- | --- |
| `extraContainers` | `spec.template.spec.containers`, after `mctl-api` | Full container specs. Nothing from the main container (env, envFrom, mounts) is shared. |
| `extraVolumes` | `spec.template.spec.volumes`, after the chart's own | Appended, never replaces. |
| `extraVolumeMounts` | `volumeMounts` of the `mctl-api` container only | A sidecar lists its own mounts in its spec. |
| `podSecurityContext` | `spec.template.spec.securityContext` | Emitted only when non-empty. |
| `containerSecurityContext` | `securityContext` of the `mctl-api` container only | Emitted only when non-empty. Sidecars carry their own. |

## Pod Security Admission (restricted)

The main `mctl-api` container is NOT restricted-clean with the chart defaults:
it has no container securityContext (no `allowPrivilegeEscalation: false`, no
`capabilities.drop: [ALL]`) and the pod sets none. To pass PSA `restricted` an
operator must set all of:

```yaml
podSecurityContext:
  fsGroup: 1000
  runAsUser: 1000        # numeric uid of user "app" (Dockerfile: adduser -u 1000)
  runAsNonRoot: true
  seccompProfile: {type: RuntimeDefault}
containerSecurityContext:
  allowPrivilegeEscalation: false
  capabilities: {drop: [ALL]}
```

`runAsUser` is mandatory with `runAsNonRoot`: the Dockerfile says
`USER app:app`, a non-numeric user, so kubelet cannot verify it is non-root and
the container fails with `CreateContainerConfigError` without a numeric uid.

The chart injects no securityContext for sidecars: every entry of
`extraContainers` must carry its own `allowPrivilegeEscalation: false`,
`capabilities.drop: [ALL]`, `runAsNonRoot: true` and
`seccompProfile.type: RuntimeDefault` (and `runAsUser` if its image user is
not numeric).

## fsGroup

`podSecurityContext.fsGroup` makes kubelet group-own every volume on the pod,
which is what a Secret or emptyDir shared with a sidecar needs when the
container runs as uid 1000. It also affects the existing secret volumes (see
the `gitops-ssh` / `github-app-token` notes in `deployment.yaml`), so set it
per deployment, not as a chart default.

## Changing the default render on purpose

`UPDATE_GOLDEN=1 go test ./helm/ -run Golden`, then read the diff. Use
`-count=1` when mutating templates by hand: Go's test cache does not see files
that only the `helm` subprocess reads.
