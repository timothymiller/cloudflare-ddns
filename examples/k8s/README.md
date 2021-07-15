
Create config File

```
cp ../../config-example.json config-cloudflare-ddns-secret.js
```

Edit config.json (vim, nvim, nano... )
```
${EDITOR} config-cloudflare-ddns-secret.js
```

Create config file as Secret.

```
kubectl create secret generic config-cloudflare-ddns --from-file=config-cloudflare-ddns-secret.js --dry-run=client -oyaml -n ddns > config-cloudflare-ddns-Secret.yaml
```

apply this secret

```
kubectl apply -f config-cloudflare-ddns-Secret.yaml
```

apply this Deployment

```
kubectl apply -f cloudflare-ddns-Deployment.yaml
```
