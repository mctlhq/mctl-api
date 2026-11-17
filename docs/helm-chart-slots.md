# Helm chart extension slots

The chart (`helm/`) exposes four optional slots so a deployment can add a
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

## Pod Security Admission (restricted)

The chart injects no securityContext of its own and none for sidecars. Under
PSA `restricted` every entry of `extraContainers` must carry its own
`allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`,
`runAsNonRoot: true` and `seccompProfile.type: RuntimeDefault`.
`podSecurityContext` accepts `fsGroup`, `runAsNonRoot` and `seccompProfile`
and is compatible with `restricted` as long as none of them is loosened.

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
