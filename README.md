# Kubernetes Cert Manager Operator

This operator can help you to generate self signed certificates inside a Kubernetes Cluster using a
`Certificate` CRD.

Link to a working example: https://asciinema.org/a/676346

<img src="assets/demo.gif" width=650px; />

## How to use?

### Pre-requisites:
* A running Kubernetes Cluster
* Docker
* kubectl

### Follow along!

* Apply the CRDs into your cluster.
    ```
    kubectl apply -f config/crd/bases 
    ```

* Apply the RBAC configs in your cluster. This will create a ServiceAccount in `cert-manager` namespace
  which will allow our operator to make requests to the K8s API Server.
    ```
    kubectl apply -f config/rbac/ 
    ```

* Deploy the Operator.
    ```
    kubectl apply -f demo/deployment.yaml  
    ```

* Wait for the Operator pod to be in the running state. Once it's up, we can apply our `Certificate` resource which will
  create a new Self Signed TLS Certificate and store it in a Secret inside our Cluster.
    ```
    kubectl apply -f demo/certificate.yaml 
    ```

* Our operator shoudl detect that a new resource was created of type `Certificate` and reconciling the object.
  It will then create a secret in our cluster which we can check by:
    ```
    kubectl get secrets  
    ```

* To test if our Certificate is valid or not, we can try to create a nginx server in our cluster with a SSL connection
  using our certificate:
    ```
    kubectl apply -f demo/nginx  
    ```

* We can now port forward our service and access it via localhost.
    ```
    kubectl port-forward service/nginx-tls-service 8443:443 -n default
    ```

* We can check by curling over the localhost port using https which proves that an SSL connection has been made.
    ```
    curl -k https://localhost:8443
    ```

## Decode and Inspect the Certificate and Key

To further validate the contents, decode the certificate and key and inspect their details.

* Extract and decode tls.crt:

  ```
  kubectl get secret my-certificate-secret -n default -o jsonpath="{.data.tls\.crt}" | base64 --decode > tls.crt

  ```

* Extract and decode tls.key:
  ```
  kubectl get secret my-certificate-secret -n default -o jsonpath="{.data.tls\.key}" | base64 --decode > tls.key
  ```

* Use OpenSSL to view the certificate details:

  ```
  openssl x509 -in tls.crt -noout -text
  ```

* Ensure that the private key is correctly formatted and valid:

  ```
  openssl rsa -in tls.key -check
  ```
  You should see a confirmation like:

  ```
  RSA key ok
  ```

## Want to try it out locally? Follow the below guide

* Create an OCI Artifact for the Operator which you can later use to deploy in your cluster.
    ```
    docker buildx build -t <remote-registry>/<image-name>:<image-tag> . 
    ```

* Push your image to the remote registry.
    ```
    docker push <remote-registry>/<image-name>:<image-tag> 
    ```

* You can then use this image to deploy any changes to operator.
