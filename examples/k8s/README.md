
Create config File

``` bash
cp ../../config-example.json config-cloudflare-ddns-secret.js
```

Edit config.json (vim, nvim, nano... )
``` bash
${EDITOR} config-cloudflare-ddns-secret.js
```

Create config file as Secret.

``` bash
kubectl create secret generic config-cloudflare-ddns --from-file=config-cloudflare-ddns-secret.js --dry-run=client -oyaml -n ddns > config-cloudflare-ddns-Secret.yaml
```

apply this secret

``` bash
kubectl apply -f config-cloudflare-ddns-Secret.yaml
rm config-cloudflare-ddns-secret.js # recomended Just keep de secret on Kubernetes Cluster
```

apply this Deployment

``` bash
kubectl apply -f cloudflare-ddns-Deployment.yaml
```
