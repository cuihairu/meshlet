#[cfg(test)]
mod forwarding_tests {
    use crate::service::{
        create_alias, create_host_forward, create_invite, create_network, create_route, enroll,
        list_devices, record_diagnostics, CreateAliasRequest, CreateHostForwardRequest,
        CreateInviteRequest, CreateNetworkRequest, CreateRouteRequest, EnrollRequest, MeshState,
        ServiceError,
    };
    use meshlet_domain::{DeviceId, Ipv4Cidr};
    use meshlet_network::NetworkDiagnostics;
    use serde_json::{json, Value};

    fn network(state: &mut MeshState, overlay: &str) -> (String, String) {
        let id = create_network(
            state,
            CreateNetworkRequest {
                name: overlay.into(),
                overlay_cidr: overlay.into(),
            },
        )
        .unwrap()
        .id;
        let invite = create_invite(
            state,
            &id,
            CreateInviteRequest {
                expires_at: None,
                max_uses: None,
            },
        )
        .unwrap();
        let device = enroll(
            state,
            EnrollRequest {
                invite_token: invite.token,
                device_name: id.clone(),
                public_key: format!("key-{id}"),
                platform: "linux".into(),
            },
        )
        .unwrap();
        (id, device.device_id)
    }

    fn snapshot(state: &MeshState) -> Value {
        let revisions: std::collections::BTreeMap<_, _> = state
            .networks
            .keys()
            .map(|id| {
                (
                    id.clone(),
                    state
                        .ledger
                        .revisions(&meshlet_domain::NetworkId(id.clone()))
                        .iter()
                        .map(crate::revision::to_revision_view)
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        json!({"routes": state.lan_routes, "aliases": state.aliases, "sequence": state.route_seq, "networks": state.networks.keys().collect::<std::collections::BTreeSet<_>>(), "revisions": revisions})
    }

    // Prepare an Alias route before the mutation snapshot: creating the mapping
    // must not consume a revision or id when its forwarding prefix conflicts.
    fn prepare(
        state: &mut MeshState,
        net: &str,
        gateway: &str,
        kind: &str,
        target: &str,
    ) -> Option<String> {
        (kind == "alias").then(|| {
            create_route(
                state,
                net,
                CreateRouteRequest {
                    gateway_device_id: gateway.into(),
                    destination_cidr: target.into(),
                    route_mode: Some("alias".into()),
                    return_path_mode: "controlled_snat".into(),
                },
            )
            .unwrap()
            .id
        })
    }

    fn publish(
        state: &mut MeshState,
        net: &str,
        gateway: &str,
        kind: &str,
        prefix: &str,
        target: &str,
        route: Option<String>,
    ) -> Result<(), ServiceError> {
        match kind {
            "direct" => create_route(
                state,
                net,
                CreateRouteRequest {
                    gateway_device_id: gateway.into(),
                    destination_cidr: prefix.into(),
                    route_mode: None,
                    return_path_mode: "dual_route".into(),
                },
            )
            .map(|_| ()),
            "alias" => create_alias(
                state,
                net,
                CreateAliasRequest {
                    lan_route_id: route.unwrap(),
                    alias_cidr: prefix.into(),
                    translation_mode: None,
                },
            )
            .map(|_| ()),
            "host" => create_host_forward(
                state,
                net,
                CreateHostForwardRequest {
                    gateway_device_id: gateway.into(),
                    target_ipv4: target.parse::<Ipv4Cidr>().unwrap().network(),
                    alias_ipv4: prefix.parse::<Ipv4Cidr>().unwrap().network(),
                    translation_mode: None,
                },
            )
            .map(|_| ()),
            _ => unreachable!(),
        }
    }

    #[test]
    fn forwarding_prefix_entrypoints_reject_each_other_atomically() {
        let mut cases = 0;
        for first in ["direct", "alias", "host"] {
            for second in ["direct", "alias", "host"] {
                for cross_network in [false, true] {
                    for (first_len, second_len) in [(32, 32), (24, 32), (32, 24)] {
                        if (first == "host" && first_len != 32)
                            || (second == "host" && second_len != 32)
                        {
                            continue;
                        }
                        let mut state = MeshState::default();
                        let (n1, g1) = network(&mut state, "10.240.0.0/24");
                        let (n2, g2) = if cross_network {
                            network(&mut state, "10.242.0.0/24")
                        } else {
                            (n1.clone(), g1.clone())
                        };
                        let p1 = format!(
                            "10.250.0.{}/{first_len}",
                            if first_len == 32 { 5 } else { 0 }
                        );
                        let p2 = format!(
                            "10.250.0.{}/{second_len}",
                            if second_len == 32 { 5 } else { 0 }
                        );
                        let t1 = format!(
                            "192.168.60.{}/{first_len}",
                            if first_len == 32 { 5 } else { 0 }
                        );
                        let t2 = format!(
                            "192.168.61.{}/{second_len}",
                            if second_len == 32 { 5 } else { 0 }
                        );
                        let r1 = prepare(&mut state, &n1, &g1, first, &t1);
                        publish(&mut state, &n1, &g1, first, &p1, &t1, r1).unwrap();
                        let r2 = prepare(&mut state, &n2, &g2, second, &t2);
                        let before = snapshot(&state);
                        let err = publish(&mut state, &n2, &g2, second, &p2, &t2, r2).unwrap_err();
                        assert!(
                            matches!(err, ServiceError::RouteConflict(_)),
                            "{first} -> {second}: {err}"
                        );
                        assert_eq!(
                            snapshot(&state),
                            before,
                            "{first} -> {second}, cross={cross_network}, {p1}/{p2}"
                        );
                        cases += 1;
                    }
                }
            }
        }
        assert_eq!(cases, 42);
    }

    #[test]
    fn overlay_conflicts_reject_all_entries_and_creation_orders() {
        for kind in ["direct", "alias", "host"] {
            for cross in [false, true] {
                let mut state = MeshState::default();
                let (net, gw) = network(&mut state, "10.240.0.0/24");
                if cross {
                    network(&mut state, "10.242.0.0/24");
                }
                let target = "192.168.61.5/32";
                let route = prepare(&mut state, &net, &gw, kind, target);
                let before = snapshot(&state);
                let prefix = if cross {
                    "10.242.0.5/32"
                } else {
                    "10.240.0.5/32"
                };
                assert!(matches!(
                    publish(&mut state, &net, &gw, kind, prefix, target, route),
                    Err(ServiceError::RouteConflict(_))
                ));
                assert_eq!(snapshot(&state), before);
            }
            let mut state = MeshState::default();
            let (net, gw) = network(&mut state, "10.240.0.0/24");
            let route = prepare(&mut state, &net, &gw, kind, "192.168.61.5/32");
            publish(
                &mut state,
                &net,
                &gw,
                kind,
                "10.250.0.5/32",
                "192.168.61.5/32",
                route,
            )
            .unwrap();
            let before = snapshot(&state);
            assert!(matches!(
                create_network(
                    &mut state,
                    CreateNetworkRequest {
                        name: "blocked".into(),
                        overlay_cidr: "10.250.0.0/24".into()
                    }
                ),
                Err(ServiceError::RouteConflict(_))
            ));
            assert_eq!(snapshot(&state), before);
        }
    }

    #[test]
    fn diagnostics_roundtrip_record_list_clear() {
        let mut state = MeshState::default();
        let (_net, device_id) = network(&mut state, "10.240.0.0/24");
        let snap = NetworkDiagnostics {
            collected_at: Some("2026-11-01T04:00:00Z".into()),
            route_table: vec!["default via 10.0.0.1 dev eth0".into()],
            interfaces: vec![meshlet_network::InterfaceDiagnostic {
                name: "wg-mlt".into(),
                ipv4: "10.240.0.4".into(),
                prefix: Some(24),
                state: "up".into(),
                mtu: Some(1420),
            }],
            wg: vec![meshlet_network::WgPeerDiagnostic {
                public_key: "pk-hub".into(),
                endpoint: "106.14.216.177:51820".into(),
                allowed_ips: "10.240.0.0/16".into(),
                last_handshake: 1_730_000_000,
                rx_bytes: 4096,
                tx_bytes: 128,
            }],
        };
        let did = DeviceId(device_id);
        record_diagnostics(&mut state, &did, Some(snap.clone()));
        let views = list_devices(&state, &_net).unwrap();
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].diagnostics, Some(snap));
        record_diagnostics(&mut state, &did, None);
        let views = list_devices(&state, &_net).unwrap();
        assert_eq!(views[0].diagnostics, None);
    }

    #[test]
    fn invalid_host_unit_does_not_consume_ids_or_revisions() {
        let mut state = MeshState::default();
        let (net, gw) = network(&mut state, "10.240.0.0/24");
        let before = snapshot(&state);
        assert!(publish(
            &mut state,
            &net,
            &gw,
            "host",
            "192.168.61.5/32",
            "192.168.61.5/32",
            None
        )
        .is_err());
        assert_eq!(snapshot(&state), before);
    }
}
