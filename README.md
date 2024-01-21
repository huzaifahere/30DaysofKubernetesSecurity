# 30DaysofKubernetesSecurity
30 Days of Kubernetes Security is a learning experience that will help you master the security best practices for Kubernetes. 

In this 30-day challenge, you will learn about the following from Kubernetes perspective:
- Pod Security Standards
- Role-Based Access Control (RBAC)
- Network Policies
- Vulnerability scanning and patching
- Logging and monitoring
- Data Security




**Week 1:**

- **Day 1:** Start with the basics of Kubernetes security.
    - https://kubernetes.io/docs/tutorials/kubernetes-basics/
    - https://kubernetes.io/docs/tutorials/security/
    - https://medium.com/the-programmer/kubernetes-fundamentals-for-absolute-beginners-architecture-components-1f7cda8ea536
- **Day 2:** Learn about Kubernetes attack vectors and how to secure them.
    - [Kubernetes Security: Attacking and Defending K8s Clusters](https://www.youtube.com/watch?v=Ek1oaGwfli0).
    - **[Kubernetes Security For Beginners | Part 1](https://www.youtube.com/watch?v=Adm9wQdkzxg)**
- **Day 3:** Learn how to secure Kubernetes clusters using network policies.
    - https://blog.digitalis.io/kubernetes-network-policies-with-calico-f037064efc4a
    - https://www.tigera.io/blog/deep-dive/what-you-cant-do-with-kubernetes-network-policies-unless-you-use-calico-node-specific-policies/
    - [https://medium.com/@bijit211987/kubernetes-network-policy-secure-your-cluster-4477f5f8bc8d#:~:text=Best practices for applying Kubernetes network policies&text=Only allow inter-namespace communication,receive non-cluster network traffic](https://medium.com/@bijit211987/kubernetes-network-policy-secure-your-cluster-4477f5f8bc8d#:~:text=Best%20practices%20for%20applying%20Kubernetes%20network%20policies&text=Only%20allow%20inter%2Dnamespace%20communication,receive%20non%2Dcluster%20network%20traffic).
- **Day 4:** Learn how to secure Kubernetes secrets
    - https://medium.com/@MetricFire/kubernetes-secrets-management-70e0d269e813
    - https://snyk.io/blog/best-practices-for-kubernetes-secrets-management/
- **Day 5:** Learn how to secure Kubernetes with RBAC
    - https://learnk8s.io/rbac-kubernetes
    - https://www.schutzwerk.com/en/blog/kubernetes-privilege-escalation-01/
    - https://sysdig.com/learn-cloud-native/kubernetes-security/kubernetes-rbac

**Week 2:**

- **Day 6:** Learn how to secure Kubernetes with Pod Security
    - https://kubernetes.io/docs/concepts/security/pod-security-standards/
    - https://snyk.io/blog/understanding-kubernetes-pod-security-standards/
- **Day 7:** Learn how to secure Kubernetes with admission controllers.
    - https://kubernetes.io/docs/concepts/security/pod-security-admission/
- **Day 8:** Learn how to secure Kubernetes with Open Policy Agent.
    - https://www.openpolicyagent.org/docs/latest/kubernetes-tutorial/
    - https://medium.com/@onixoni72/securing-kubernetes-with-open-policy-agent-opa-67167157d477
    - **Using Open Policy Agent to Safeguard Kubernetes** https://www.styra.com/blog/using-open-policy-agent-to-safeguard-kubernetes/
- **Day 9:** Learn how to secure Kubernetes with Falco
    - https://sysdig.com/blog/intro-runtime-security-falco/
    - **[Getting started with container runtime security using Falco](https://www.youtube.com/watch?v=VEFaGjfjfyc)**
- **Day 10:** Learn how to secure Kubernetes with Istio.
    - https://www.giantswarm.io/blog/improving-security-with-istio
    - [https://istio.io/v1.9/docs/ops/best-practices/security/#:~:text=To further secure traffic%2C Istio,9080 of our reviews application](https://istio.io/v1.9/docs/ops/best-practices/security/#:~:text=To%20further%20secure%20traffic%2C%20Istio,9080%20of%20our%20reviews%20application).

**Week 3:**

- **Day 11:** Learn how to secure Kubernetes with Helm
    - https://www.aquasec.com/cloud-native-academy/kubernetes-101/kubernetes-helm/
    - https://bridgecrew.io/wp-content/uploads/kubernetes-helm-security-research.pdf
    - https://sysdig.com/blog/how-to-secure-helm/
    - https://v2.helm.sh/docs/securing_installation/
- **Day 12:** Learn how to secure Kubernetes with Kube-bench
    - [https://medium.com/@CloudifyOps/securing-kubernetes-with-cis-benchmark-leveraging-kube-bench-and-grafana-for-enhanced-visibility-8314391b7e81#:~:text=You can run Kube-Bench,run master checks when possible](https://medium.com/@CloudifyOps/securing-kubernetes-with-cis-benchmark-leveraging-kube-bench-and-grafana-for-enhanced-visibility-8314391b7e81#:~:text=You%20can%20run%20Kube%2DBench,run%20master%20checks%20when%20possible).
    - https://www.linkedin.com/pulse/securing-kubernetes-cluster-using-kubescape-kube-bench-razorops/
- **Day 13:** Learn how to secure Kubernetes with Trivy
    - https://www.kitploit.com/2019/11/trivy-simple-and-comprehensive.html
    - https://betterprogramming.pub/integrating-docker-container-scans-in-ci-builds-991a94b9132b
- **Day 14:** Learn how to monitor Kubernetes with Sysdig.
    - https://kubernetes.io/blog/2015/11/monitoring-kubernetes-with-sysdig/
- **Day 15:** Learn how to secure Kubernetes using threat modeling
    - https://www.trendmicro.com/vinfo/us/security/news/security-technology/a-deep-dive-into-kubernetes-threat-modeling

**Week 4:**

- **Day 16:** Learn how to secure Kubernetes with Calico.
    - https://docs.tigera.io/calico/latest/network-policy/get-started/calico-policy/calico-network-policy
    - https://www.tigera.io/blog/kubernetes-networking-with-calico/
- **Day 17:** Learn how to secure Kubernetes with Cilium
    - https://www.youtube.com/watch?v=he2sLeJsMqU
    - https://www.youtube.com/watch?app=desktop&v=j00k6qwxRhI
- **Day 18:** Learn how to secure Kubernetes with Kube-hunter
    - https://github.com/aquasecurity/kube-hunter
- **Day 19:** Learn how to secure Kubernetes with Kubeaudit.
    - https://kloudle.com/academy/auditing-kubernetes-with-kubeaudit-conducting-an-assessment/
    - https://www.securecodebox.io/docs/scanners/kubeaudit/
- **Day 20:** Learn how to secure Container using Seccomp
- https://kubernetes.io/docs/tutorials/security/seccomp/

**Lab:**

- **Day 21-30:** Practice what you have learned in a lab environment.
    - https://madhuakula.com/kubernetes-goat/docs/scenarios
    
    **OWASP Kubernetes Top 10**
    
    **Kubernetes Goat Mapped Scenarios**
    
    **[K01: Insecure Workload Configurations](https://madhuakula.com/kubernetes-goat/docs/owasp-kubernetes-top-ten#-k01---insecure-workload-configurations)**
    
    --**[DIND (docker-in-docker) exploitation](https://madhuakula.com/kubernetes-goat/docs/scenarios/scenario-2/docker-in-docker-exploitation-in-kubernetes-containers)**
    
    --**[DoS the Memory/CPU resources](https://madhuakula.com/kubernetes-goat/docs/scenarios/scenario-13/denial-of-service-memory-and-cpu-resources-in-kubernetes-cluster)**
    
    **[K02: Supply Chain Vulnerabilities](https://madhuakula.com/kubernetes-goat/docs/owasp-kubernetes-top-ten#-k02---supply-chain-vulnerabilities)**
    
    --**[Attacking private registry](https://madhuakula.com/kubernetes-goat/docs/scenarios/scenario-7/attacking-private-container-registry-in-kubernetes)**
    
    **[K03: Overly Permissive RBAC](https://madhuakula.com/kubernetes-goat/docs/owasp-kubernetes-top-ten#-k03---overly-permissive-rbac)**
    
    --**[RBAC least privileges misconfiguration](https://madhuakula.com/kubernetes-goat/docs/scenarios/scenario-16/rbac-least-privileges-misconfiguration-in-kubernetes-cluster)**
    
    **[K04: Lack of Centralized Policy Enforcement](https://madhuakula.com/kubernetes-goat/docs/owasp-kubernetes-top-ten#-k04---lack-of-centralized-policy-enforcement)**
    
    --**[Securing Kubernetes Clusters using Kyverno Policy Engine](https://madhuakula.com/kubernetes-goat/docs/scenarios/scenario-22/securing-kubernetes-clusters-using-kyverno-policy-engine)**
    
    **[K05: Inadequate Logging and Monitoring](https://madhuakula.com/kubernetes-goat/docs/owasp-kubernetes-top-ten#-k05---inadequate-logging-and-monitoring)**
    
    --**[Cilium Tetragon - eBPF-based Security Observability and Runtime Enforcement](https://madhuakula.com/kubernetes-goat/docs/scenarios/scenario-21/ebpf-runtime-security-monitoring-and-detection-in-kubernetes-cluster-using-cilium-tetragon)**
    
    --**[Falco - Runtime security monitoring & detection](https://madhuakula.com/kubernetes-goat/docs/scenarios/scenario-18/runtime-security-monitoring-and-detection-in-kubernetes-cluster-using-falco)**
    
    **[K06: Broken Authentication Mechanisms](https://madhuakula.com/kubernetes-goat/docs/owasp-kubernetes-top-ten#-k06---broken-authentication-mechanisms)**
    
    --**[RBAC least privileges misconfiguration](https://madhuakula.com/kubernetes-goat/docs/scenarios/scenario-16/rbac-least-privileges-misconfiguration-in-kubernetes-cluster)**
    
    **[K07: Missing Network Segmentation Controls](https://madhuakula.com/kubernetes-goat/docs/owasp-kubernetes-top-ten#-k07---missing-network-segmentation-controls)**
    
    --**[Kubernetes namespaces bypass](https://madhuakula.com/kubernetes-goat/docs/scenarios/scenario-11/kubernetes-namespaces-bypass-from-kubernetes-cluster-pod)**
    
    --**[Secure network boundaries using NSP](https://madhuakula.com/kubernetes-goat/docs/scenarios/scenario-20/secure-kubernetes-using-network-security-policy)**
    
    **[K08: Secrets Management Failures](https://madhuakula.com/kubernetes-goat/docs/owasp-kubernetes-top-ten#-k08---secrets-management-failures)**
    
    --**[Sensitive keys in codebases](https://madhuakula.com/kubernetes-goat/docs/scenarios/scenario-1/sensitive-keys-in-codebases-in-kubernetes-containers)**
    
    **[K09: Misconfigured Cluster Components](https://madhuakula.com/kubernetes-goat/docs/owasp-kubernetes-top-ten#-k09---misconfigured-cluster-components)**
    
    --**[KubeAudit - Audit Kubernetes cluster](https://madhuakula.com/kubernetes-goat/docs/scenarios/scenario-17/auditing-the-kubernetes-cluster-using-kubeaudit)**
    
    **[K10: Outdated and Vulnerable Kubernetes Components](https://madhuakula.com/kubernetes-goat/docs/owasp-kubernetes-top-ten#-k10---outdated-and-vulnerable-kubernetes-components)**
    
    --**[Helm v2 tiller to PwN the cluster - [Deprecated]](https://madhuakula.com/kubernetes-goat/docs/scenarios/scenario-9/helm-v2-tiller-to-pwn-kubernetes-cluster-takeover)**
    

I hope this plan helps you get started with learning Kubernetes security. Let me know if you have any other questions!
