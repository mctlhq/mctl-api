# Changelog

## [4.32.7](https://github.com/mctlhq/mctl-api/compare/4.32.6...4.32.7) (2026-08-19)


### Bug Fixes

* **api:** key rate limits by the trusted client IP, not a spoofable header ([e06061a](https://github.com/mctlhq/mctl-api/commit/e06061afc12023d6ca734c417a8b4ca3f410166b))
* **api:** key rate limits by the trusted client IP, not a spoofable header ([e777525](https://github.com/mctlhq/mctl-api/commit/e777525cc3e739420dcffca70bff431c6066de9f))

## [4.32.6](https://github.com/mctlhq/mctl-api/compare/4.32.5...4.32.6) (2026-08-16)


### Bug Fixes

* **audit:** drain oldest-first, bound each lookup, test the reconciler ([d514d43](https://github.com/mctlhq/mctl-api/commit/d514d43a1a09b039b2a6db90527659e0a0a1ba12))
* **audit:** keep the terminal guard at the top level of the UPDATE ([ea96cf2](https://github.com/mctlhq/mctl-api/commit/ea96cf2e069b8b589d2f0764fa0145d925696aec))
* **audit:** page the reconciler queue, scope UpdateStatus to one row, index it ([fa0a152](https://github.com/mctlhq/mctl-api/commit/fa0a1520ce8090bec88e9b00594071fb00e6e4e8))
* **audit:** record what actually happened, not just what was submitted ([525b528](https://github.com/mctlhq/mctl-api/commit/525b52839250877cf38eefd2aec9442f37348349))
* **audit:** record what actually happened, not just what was submitted ([f940638](https://github.com/mctlhq/mctl-api/commit/f9406386e4b8f5cf9c8151644ddea714677af433))
* **oauth:** bound access-token TTL and expire stale DCR registrations ([f3d635d](https://github.com/mctlhq/mctl-api/commit/f3d635df8e1470e815e872ec3e29f175be0cba67))
* **oauth:** bound access-token TTL and expire stale DCR registrations ([f9fa393](https://github.com/mctlhq/mctl-api/commit/f9fa39320cfbb86da11893cec1cded7bec21d66e))
* **tenant:** default internet egress to closed, and let MCP set it ([bf3a44f](https://github.com/mctlhq/mctl-api/commit/bf3a44f8926100a5d55ee40b5b249d25eb5a0c5a))
* **tenant:** default internet egress to closed, and let MCP set it ([6cc17bb](https://github.com/mctlhq/mctl-api/commit/6cc17bb6dfb20a9b78e5267a9fbc2711d97a19ba))
* **whoami:** stop hiding the admins namespace ([6784cce](https://github.com/mctlhq/mctl-api/commit/6784cce5177660dbd57ba0240dba8c12a20ce00a))
* **whoami:** stop hiding the admins namespace ([3a1832b](https://github.com/mctlhq/mctl-api/commit/3a1832b78a47478901d960cf253aa439ffcd5718))

## [4.32.5](https://github.com/mctlhq/mctl-api/compare/4.32.4...4.32.5) (2026-08-16)


### Bug Fixes

* **oauth:** bound client_name on the registration success log too ([ca41c90](https://github.com/mctlhq/mctl-api/commit/ca41c903b996efd0be0c53692d4991ff7a1befcc))
* **oauth:** bound the DCR client registry and raise the register limit ([bc0c066](https://github.com/mctlhq/mctl-api/commit/bc0c066d68db0db8f2cbd919e82959f2bfefe672))
* **oauth:** bound the DCR client registry and raise the register limit ([217e225](https://github.com/mctlhq/mctl-api/commit/217e225c7210e454eaade4ccd0b5725bf229f343))
* **oauth:** do not answer 200 to a revocation that never happened ([82d75fd](https://github.com/mctlhq/mctl-api/commit/82d75fd1279fb9a7d74902ceee8b4bea2cdc34bf))
* **oauth:** harden registration body, truncation and cache headers ([7439573](https://github.com/mctlhq/mctl-api/commit/74395737f02821a98536e2087675e6abb85697a3))
* **oauth:** name the rejected redirect_uri on failed registration ([6a7f7bc](https://github.com/mctlhq/mctl-api/commit/6a7f7bca32697ba86966091bd717d066789e5b76))
* **oauth:** name the rejected redirect_uri on failed registration ([f5e1437](https://github.com/mctlhq/mctl-api/commit/f5e14377ae7c488f5aca134c53eefb0b355d167a))
* **oauth:** reject a revocation request that carries no token ([2ef473e](https://github.com/mctlhq/mctl-api/commit/2ef473e282a3b62ca9c97ded0ab59ae0675735f8))

## [4.32.4](https://github.com/mctlhq/mctl-api/compare/4.32.3...4.32.4) (2026-08-15)


### Bug Fixes

* **api:** drive shutdown from one root signal context ([7af8e96](https://github.com/mctlhq/mctl-api/commit/7af8e966c118b76db49b53542549a4842379593c)), closes [#166](https://github.com/mctlhq/mctl-api/issues/166)
* **api:** release the signal handler without defer, and check ctx before the wait ([aba2708](https://github.com/mctlhq/mctl-api/commit/aba2708f2a3fafed448aa9299aad67097b0c06e2)), closes [#166](https://github.com/mctlhq/mctl-api/issues/166)
* **api:** retry optional store init instead of giving up on the first try ([839b3cc](https://github.com/mctlhq/mctl-api/commit/839b3ccc0b309e26b620d521ba2eefdc9b1af7e7))
* **api:** retry optional store init instead of giving up on the first try ([5affa40](https://github.com/mctlhq/mctl-api/commit/5affa405aa5e9940f5cc79f783b732f1da0420fa)), closes [#166](https://github.com/mctlhq/mctl-api/issues/166)
* **api:** share one init budget across stores and honour SIGTERM ([bb729f4](https://github.com/mctlhq/mctl-api/commit/bb729f405c68c8a4e9f15e3dda1bd86cdb349ffb)), closes [#166](https://github.com/mctlhq/mctl-api/issues/166)

## [4.32.3](https://github.com/mctlhq/mctl-api/compare/4.32.2...4.32.3) (2026-08-15)


### Bug Fixes

* **api:** omit DSN from TLS parse errors ([ac52260](https://github.com/mctlhq/mctl-api/commit/ac52260428d9deaedc65abcdb3adc5e68ff8d876))
* **api:** require CNPG TLS and record audit IP/UA ([97bbb69](https://github.com/mctlhq/mctl-api/commit/97bbb695b5c2ac0573073c504cabbd2798979e65))
* **api:** require CNPG TLS and record audit IP/UA ([c6f33fe](https://github.com/mctlhq/mctl-api/commit/c6f33feb49a7a97c360e2eb45f0affa27550a4bb))
* **api:** take rightmost XFF hop and refuse TLS parse fallback ([0ee216d](https://github.com/mctlhq/mctl-api/commit/0ee216d0053aa00b8093ae56a5136f8a3ecf4cd7))

## [4.32.2](https://github.com/mctlhq/mctl-api/compare/4.32.1...4.32.2) (2026-08-14)


### Bug Fixes

* **api:** close SOC F12-F14 readiness, metrics, OAuth hardening ([98c0f6e](https://github.com/mctlhq/mctl-api/commit/98c0f6e87ced928972c77fdd23dd4945fd283b9d))
* **api:** close SOC F12-F14 readiness, metrics, OAuth hardening ([8422446](https://github.com/mctlhq/mctl-api/commit/84224462610ecb5bd10b5a8e800a435944be5fdc))
* **api:** isolate readyz probes and hide error details ([4d88a7a](https://github.com/mctlhq/mctl-api/commit/4d88a7a970152413059aee89fa5ebad754997851))

## [4.32.1](https://github.com/mctlhq/mctl-api/compare/4.32.0...4.32.1) (2026-08-14)


### Bug Fixes

* **oauth:** accept loopback redirect URIs per RFC 8252 §7.3 ([1ea3f85](https://github.com/mctlhq/mctl-api/commit/1ea3f8523af6e82704381684682a6683562cd998))
* **oauth:** accept loopback redirect URIs per RFC 8252 §7.3 ([e7f0786](https://github.com/mctlhq/mctl-api/commit/e7f0786d48f8d97ecb70227489dc403cd484cf31))
* **oauth:** compare loopback host case-insensitively ([bd22918](https://github.com/mctlhq/mctl-api/commit/bd229181cfd9168d683b15dfe86dc42cb90de711))
* **oauth:** reject userinfo and backslash in loopback redirects ([6cbb888](https://github.com/mctlhq/mctl-api/commit/6cbb888591cabe904a47cde3814bf5bcfd94e19d))
* **oauth:** scope registered redirect URIs to the client that registered them ([f24b29d](https://github.com/mctlhq/mctl-api/commit/f24b29d6e534de8f66d5d7216dd91cee2989f7c8))
* **oauth:** validate redirect_uri before any error can redirect to it ([04c5aa8](https://github.com/mctlhq/mctl-api/commit/04c5aa8b4efb5b9fca588cf1f86fc24af745c3c6))

## [4.32.0](https://github.com/mctlhq/mctl-api/compare/4.31.0...4.32.0) (2026-08-14)


### Features

* **mcp:** add MCP Prompts and Resources support ([327c8cd](https://github.com/mctlhq/mctl-api/commit/327c8cd29b0b7948e459647eed3747433cb60540))
* **mcp:** add MCP Prompts and Resources support ([54ebdc3](https://github.com/mctlhq/mctl-api/commit/54ebdc35aa942285c334ac6c6d5ea6636f4be295))


### Bug Fixes

* authenticate the custom-domains proxy to Backstage ([d2428b4](https://github.com/mctlhq/mctl-api/commit/d2428b4bbd06d1463b2de4de78a88a44b5f14769))
* authenticate the custom-domains proxy to Backstage ([b1375f7](https://github.com/mctlhq/mctl-api/commit/b1375f7ceb5fc19132338bfd4de51275c79ff01b))
* **lint:** index the operations catalog range instead of copying ([2180ff2](https://github.com/mctlhq/mctl-api/commit/2180ff244ffdf66f34f72ec25114680527f6bc49))
* **lint:** index the operations catalog range instead of copying ([7e41356](https://github.com/mctlhq/mctl-api/commit/7e413564427d972b641f96eead9efa253352a1c5))

## [4.31.0](https://github.com/mctlhq/mctl-api/compare/4.30.0...4.31.0) (2026-08-07)


### Features

* **docs:** add context7.json configuration for AI search indexer ([a61ccd1](https://github.com/mctlhq/mctl-api/commit/a61ccd113e2d6bf27cba012a0b37bcc3323c65ec))
* **docs:** add context7.json configuration for AI search indexer ([7a36366](https://github.com/mctlhq/mctl-api/commit/7a36366e0c9bcc9c36385eac3c8def406ce0d3e7))

## [4.30.0](https://github.com/mctlhq/mctl-api/compare/4.29.1...4.30.0) (2026-08-07)


### Features

* **api:** add POST /api/v1/workflows/events/argo-complete webhook endpoint ([776f16d](https://github.com/mctlhq/mctl-api/commit/776f16de799df503f3be5b93b0459aefacfbf36f))
* **api:** add POST /api/v1/workflows/events/argo-complete webhook endpoint ([7d33973](https://github.com/mctlhq/mctl-api/commit/7d339732046614ecf000d4013d49b1c43b0a9170))

## [4.29.1](https://github.com/mctlhq/mctl-api/compare/4.29.0...4.29.1) (2026-08-06)


### Bug Fixes

* add mctl-academy to implement/shepherd service enum ([cfe4366](https://github.com/mctlhq/mctl-api/commit/cfe43662b9de11bb09b802faeb260a31ceb331da))
* add mctl-academy to implement/shepherd service enum ([4a5186f](https://github.com/mctlhq/mctl-api/commit/4a5186f2e6c29391a8b8669b08fd0a9fc54b319d))
* reject image_repository that already carries a tag or digest ([c41464a](https://github.com/mctlhq/mctl-api/commit/c41464a65ecb1d583914ad5fe1fbd1319db300ce))
* reject image_repository that already carries a tag or digest ([5b4ce12](https://github.com/mctlhq/mctl-api/commit/5b4ce12889444e35ae3f1af5f081f654bce2bdcc))

## [4.29.0](https://github.com/mctlhq/mctl-api/compare/4.28.1...4.29.0) (2026-08-05)


### Features

* **mcp:** add mctl_create_agent and mctl_publish_agent_version tools ([84db5f1](https://github.com/mctlhq/mctl-api/commit/84db5f125648bb1576f9d11ec228e5415a03545a))
* **mcp:** add mctl_create_agent and mctl_publish_agent_version tools ([89ada4a](https://github.com/mctlhq/mctl-api/commit/89ada4a7af620cd5b27e30cb9d6508014bcec7d9))

## [4.28.1](https://github.com/mctlhq/mctl-api/compare/4.28.0...4.28.1) (2026-08-05)


### Bug Fixes

* add mctl-telegram/mctl-design/mctl-pairdesk to implement/shepherd service enum ([2aac485](https://github.com/mctlhq/mctl-api/commit/2aac485e9aa9e0ea90d5b5e0ea85cbb6b9e20053))
* add mctl-telegram/mctl-design/mctl-pairdesk to implement/shepherd service enum ([abcd2eb](https://github.com/mctlhq/mctl-api/commit/abcd2eb9f56d6998119ec6ee2c0b6342b69ad359))

## [4.28.0](https://github.com/mctlhq/mctl-api/compare/4.27.0...4.28.0) (2026-08-05)


### Features

* **agent-registry:** add agent_executions durable audit trail (phase 4) ([85ab9ea](https://github.com/mctlhq/mctl-api/commit/85ab9ea6b90a8d3bbdc1ce2b7774c77d8bf03ab3))
* **agent-registry:** add agent_executions durable audit trail (phase 4) ([b8c3fd0](https://github.com/mctlhq/mctl-api/commit/b8c3fd0440ff8651190c91f792fa3eeb82147d8c))
* **agents:** agent registry — versions, releases, promote/rollback ([157476e](https://github.com/mctlhq/mctl-api/commit/157476ee80fa8241c40482c27eb1487362acd3ee))
* **agents:** agent registry — versions, releases, promote/rollback ([933cc05](https://github.com/mctlhq/mctl-api/commit/933cc052e230e09f0044831c8470502fe0636ffd))
* **mcp:** wire mctl_trigger_issue use_temporal flag (phase 4) ([162f8fc](https://github.com/mctlhq/mctl-api/commit/162f8fc5e71a75dd35146a33b1b19a85b6fbc191))
* **mcp:** wire mctl_trigger_issue use_temporal flag (phase 4) ([5a19538](https://github.com/mctlhq/mctl-api/commit/5a1953805e016b1e02b7abfa5276044484f2eaaa))


### Bug Fixes

* **agents:** make promote/rollback transactional, add handler tests ([d5f2ef2](https://github.com/mctlhq/mctl-api/commit/d5f2ef2a24375410ff1c99243f3cb767deea2263))
* idempotent execution records, environment validation (PR [#128](https://github.com/mctlhq/mctl-api/issues/128) review) ([19c8dbf](https://github.com/mctlhq/mctl-api/commit/19c8dbf056be0c0e409a5a88784bcc9f0e9109eb))
* rate-limit dev-loop writes, real auth test coverage, proper error mapping (PR [#129](https://github.com/mctlhq/mctl-api/issues/129) review) ([6b41901](https://github.com/mctlhq/mctl-api/commit/6b41901a5707bd4a01a7d59946c8064130abdf6d))
* suppress gosec G101 false positive on DevLoopWorkflowType ([3322e03](https://github.com/mctlhq/mctl-api/commit/3322e039b838a80ff773df00ac7e46a46b9845d1))
* validate phase, cap oversized limit, add target_repo (PR [#128](https://github.com/mctlhq/mctl-api/issues/128) review) ([903da01](https://github.com/mctlhq/mctl-api/commit/903da013ac1b0bbdbc2e4b1b4044a00c526e2319))

## [4.27.0](https://github.com/mctlhq/mctl-api/compare/4.26.0...4.27.0) (2026-08-01)


### Features

* **logs:** add mctl_get_workflow_logs for Argo step logs ([80d7c5a](https://github.com/mctlhq/mctl-api/commit/80d7c5ae5dbc786fa78e13b2e3258a52cdc54865))
* **vault:** authenticate to Vault with the pod ServiceAccount ([ed72aea](https://github.com/mctlhq/mctl-api/commit/ed72aea7fe269292dc9e6329d012ddcef0d96c61))
* **vault:** authenticate to Vault with the pod ServiceAccount ([24ecc64](https://github.com/mctlhq/mctl-api/commit/24ecc6410ea1dfcf6ffbb7feeebafec5606f3990))


### Bug Fixes

* **lint:** satisfy golangci-lint (errcheck, gosec) on log archive tests ([de9eb86](https://github.com/mctlhq/mctl-api/commit/de9eb869f1de93f9b34a966d992c5dd9d046358d))
* **lint:** silence two gosec false positives with rationale ([db8aad1](https://github.com/mctlhq/mctl-api/commit/db8aad1de2af0b6f33c5507617a2d7a2ce8c7267))
* **logs:** address Codex review findings on workflow log archive ([234dbf7](https://github.com/mctlhq/mctl-api/commit/234dbf75040d5eca2de2096e0d90d12a91d75675))
* **vault:** decouple login from caller context, back off after fallback, fix hardExpiry for non-expiring tokens ([6063d51](https://github.com/mctlhq/mctl-api/commit/6063d51ac358e65250ef5d28f0a758ce4f41c78c))
* **workflows:** distinguish not-found from cluster errors in GetWorkflow ([8c55ec7](https://github.com/mctlhq/mctl-api/commit/8c55ec786ff95cb06fa010254946d0812c7b9c23))
* **workflows:** distinguish not-found from cluster errors in GetWorkflow ([3f7b0ac](https://github.com/mctlhq/mctl-api/commit/3f7b0ac400432b7c2c69852518a14007fdd73373))
* **workflows:** fall back to live k8s lookup for cron-driven runs ([37933a4](https://github.com/mctlhq/mctl-api/commit/37933a4df096c89fb2d9b3ccd06982c97a8267a8))
* **workflows:** fall back to live k8s lookup for cron-driven runs ([b4ef61e](https://github.com/mctlhq/mctl-api/commit/b4ef61e4c8d7227942c2cbc4a2e0ff6b7a3f9c34))

## [4.26.0](https://github.com/mctlhq/mctl-api/compare/4.25.0...4.26.0) (2026-07-30)


### Features

* **oauth:** add RFC 9728 Protected Resource Metadata discovery ([b90a03c](https://github.com/mctlhq/mctl-api/commit/b90a03c4ee285c9f3dae0522ddc7c35bf0e62e1f))
* **oauth:** add RFC 9728 Protected Resource Metadata discovery ([15235f2](https://github.com/mctlhq/mctl-api/commit/15235f22760eb507ce5c377ce661deef0ed1738a))


### Bug Fixes

* identify the correct resource in the root PRM document ([1194cfd](https://github.com/mctlhq/mctl-api/commit/1194cfddc37ca3bc1a66102c8efaf270ae52adcc))

## [4.25.0](https://github.com/mctlhq/mctl-api/compare/4.24.2...4.25.0) (2026-07-30)


### Features

* add health_check_path param to deploy-service operation ([1e6543b](https://github.com/mctlhq/mctl-api/commit/1e6543b1c9aeba06318fc7ec4a9783a9f2ccf4b3))


### Bug Fixes

* address review findings on grace-window locking, errors, and CI isolation ([a4d0b16](https://github.com/mctlhq/mctl-api/commit/a4d0b16366347b0d2a0c5e61e54d1b652dc75549))
* **oauth:** recover refresh-token rotation races instead of failing them ([86795a8](https://github.com/mctlhq/mctl-api/commit/86795a8b1d7850cc28db468af8f192c1cf9e7281))
* **oauth:** recover refresh-token rotation races instead of failing them ([ed2b66c](https://github.com/mctlhq/mctl-api/commit/ed2b66c158eab0804a5663d44734c23354b750ae))
* silence gosec false positive on the rotation domain-separation constant ([1304204](https://github.com/mctlhq/mctl-api/commit/1304204bf41a3163ac5acdaec24e8c277b54ba9d))

## [4.24.2](https://github.com/mctlhq/mctl-api/compare/4.24.1...4.24.2) (2026-07-29)


### Bug Fixes

* remove implementer force retries from API ([53e17bc](https://github.com/mctlhq/mctl-api/commit/53e17bcde69ca2208183df4fc1c4723b88bc821f))
* remove implementer force retries from API ([b8b675b](https://github.com/mctlhq/mctl-api/commit/b8b675bc0a785db58ca175956e849545b31a61ef))

## [4.24.1](https://github.com/mctlhq/mctl-api/compare/4.24.0...4.24.1) (2026-07-25)


### Bug Fixes

* **mcp:** expose dockerfile_path, image_tag, secret_env_vars, skip_health_check on mctl_deploy_service ([ba77205](https://github.com/mctlhq/mctl-api/commit/ba7720510c731fc47b14fbf970f005ffff059213))
* **mcp:** expose dockerfile_path, image_tag, secret_env_vars, skip_health_check on mctl_deploy_service ([6cc2f42](https://github.com/mctlhq/mctl-api/commit/6cc2f428ba983ae1114c64f2209572af0c6177bf))

## [4.24.0](https://github.com/mctlhq/mctl-api/compare/4.23.1...4.24.0) (2026-07-23)


### Features

* **alerts:** fingerprint-based dedup for incident creation ([12d9bd9](https://github.com/mctlhq/mctl-api/commit/12d9bd9a599c8f50c935531f6268a699f9908d4d))
* **alerts:** fingerprint-based dedup for incident creation ([898d6af](https://github.com/mctlhq/mctl-api/commit/898d6af4c2b1792a56f5e1022b0b30c0cf8aa2dd))


### Bug Fixes

* **alerts:** ignore caller-supplied occurrence_count, fix evidence on dedup hit ([0f648de](https://github.com/mctlhq/mctl-api/commit/0f648deb32c3c46e3e08bb6af63a520ead53eaab))
* **alerts:** reject cross-tenant id collisions instead of leaking the row ([007d813](https://github.com/mctlhq/mctl-api/commit/007d81384777ad8765ba5598e13f3cd153ee8b63))
* **alerts:** scope fingerprint dedup by tenant, handle id-retry ([34b2961](https://github.com/mctlhq/mctl-api/commit/34b2961ba57fa8c7036da3f61849f1204948be63))
* **ci:** preserve zero diff-line count in Claude review ([#103](https://github.com/mctlhq/mctl-api/issues/103)) ([83d71e0](https://github.com/mctlhq/mctl-api/commit/83d71e0b0f2107e39461270a3fa11238af0c3e80))

## [4.23.1](https://github.com/mctlhq/mctl-api/compare/4.23.0...4.23.1) (2026-07-12)


### Bug Fixes

* **api:** explicitly empty tenant allowlist now denies all skill enables ([5f6ec5c](https://github.com/mctlhq/mctl-api/commit/5f6ec5c9dcc7518603251c402fc3344e2aca4a6a))
* **api:** explicitly empty tenant allowlist now denies all skill enables ([c2d9e69](https://github.com/mctlhq/mctl-api/commit/c2d9e692c2f76f05206fec9d54cfda238482f139))

## [4.23.0](https://github.com/mctlhq/mctl-api/compare/4.22.0...4.23.0) (2026-07-11)


### Features

* add MCP trigger for mctl-agents incident responder ([0ba2259](https://github.com/mctlhq/mctl-api/commit/0ba2259a3cd1ffdcdc66f532832ec16faa552b8d))
* add MCP trigger for mctl-agents incident responder ([61e6d92](https://github.com/mctlhq/mctl-api/commit/61e6d92714d3b98ced3feaec743bccefc0cbf34f))

## [4.22.0](https://github.com/mctlhq/mctl-api/compare/4.21.2...4.22.0) (2026-07-10)


### Features

* add platform skill registry API ([994482a](https://github.com/mctlhq/mctl-api/commit/994482a341333a9e0399ab4247ccf0af483caf9a))
* add platform skill registry API ([870b81e](https://github.com/mctlhq/mctl-api/commit/870b81ef54551e9ec7bd85eb1d3b3f51cc4c60f7))
* **mcp:** expose platform skills as MCP prompt ([28838cb](https://github.com/mctlhq/mctl-api/commit/28838cbe9c3c026699fa96ccad91f4960e563301))
* **mcp:** expose platform skills as MCP prompt ([e20a03d](https://github.com/mctlhq/mctl-api/commit/e20a03db4e6531031b9a16965caa58ec4fe72852))


### Bug Fixes

* address rangeValCopy lint and dead-code review nits ([9e8645a](https://github.com/mctlhq/mctl-api/commit/9e8645a2f16da3706e0500ac746b2d19dc864ecb))
* **ci:** detect claude-review SDK failure the outcome field misses ([6ba48a0](https://github.com/mctlhq/mctl-api/commit/6ba48a00bc1487f50efa4540d94b5bdf7e72211c))
* **ci:** detect claude-review SDK failure the outcome field misses ([7abd32c](https://github.com/mctlhq/mctl-api/commit/7abd32c5ed377efa20ad73d29839f9b7a401fa5a))
* close platform skill review-gate findings ([a436aa7](https://github.com/mctlhq/mctl-api/commit/a436aa77b7563713d1996cdb2477eafa57e2047e))

## [4.21.2](https://github.com/mctlhq/mctl-api/compare/4.21.1...4.21.2) (2026-07-07)


### Bug Fixes

* bump Docker builder image to golang:1.26-alpine ([07b2343](https://github.com/mctlhq/mctl-api/commit/07b23433b4c0c7cd4c3627bfef6834d899601682))
* bump Docker builder image to golang:1.26-alpine ([d4ee340](https://github.com/mctlhq/mctl-api/commit/d4ee340b458c309587e2afb156764475a53eb078))

## [4.21.1](https://github.com/mctlhq/mctl-api/compare/4.21.0...4.21.1) (2026-07-07)


### Bug Fixes

* **gitops:** reset diverged local cache instead of failing ff-only pull ([e69bde3](https://github.com/mctlhq/mctl-api/commit/e69bde3e176b1815914fe3c8747303398777518d))
* **gitops:** reset diverged local cache instead of failing ff-only pull ([1c5e0e3](https://github.com/mctlhq/mctl-api/commit/1c5e0e36c20a6323400d8eb961ea754255bb76c6))

## [4.21.0](https://github.com/mctlhq/mctl-api/compare/4.20.0...4.21.0) (2026-07-02)


### Features

* **mcp:** mctl_create_preview — build from branch support ([550b4ad](https://github.com/mctlhq/mctl-api/commit/550b4ad325c14a7cdd333d18aeedbfaf4d49fbcd))


### Bug Fixes

* **mcp:** add entropy to preview tags and pattern-validate branch inputs ([0f12fc6](https://github.com/mctlhq/mctl-api/commit/0f12fc6ecd8e080c2adc25f61367958bddb141c9))
* **mcp:** validate preview-deploy build-from-branch inputs server-side ([e43ae9c](https://github.com/mctlhq/mctl-api/commit/e43ae9cd10cab42316fb8a9b633523673973e490))

## [4.20.0](https://github.com/mctlhq/mctl-api/compare/4.19.0...4.20.0) (2026-05-30)


### Features

* **ci:** migrate to centralized build via release-please and mctl-gitops release-deploy ([200f0f7](https://github.com/mctlhq/mctl-api/commit/200f0f7811daca165944e9b9d350b33f0b10dce4))
* **ci:** migrate to centralized build via release-please and mctl-gitops release-deploy ([b497201](https://github.com/mctlhq/mctl-api/commit/b497201ce4c3d74c70c857e39babfc1fcb0dfee8))
