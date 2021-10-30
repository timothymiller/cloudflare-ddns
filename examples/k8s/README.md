
Create config File

``` bash
cp ../../config-example.json config.json
```

Edit config.jsonon (vim, nvim, nano... )
``` bash
${EDITOR} config.json
```

Create config file as Secret.

``` bash
kubectl create secret generic config-cloudflare-ddns --from-file=config.json --dry-run=client -oyaml -n ddns > config-cloudflare-ddns-Secret.yaml
```

apply this secret

``` bash
kubectl apply -f config-cloudflare-ddns-Secret.yaml
rm config.json # recomended Just keep de secret on Kubernetes Cluster
```

apply this Deployment

``` bash
kubectl apply -f cloudflare-ddns-Deployment.yaml
```
