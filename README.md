# Kubernetes Cert Manager Operator

This operator can help you to generate self signed certificates inside a Kubernetes Cluster using a
`Certificate` CRD.

### How to use?

#### Pre-requisites:
* A running Kubernetes Cluster
* Docker
* kubectl

#### Follow along!

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


### Want to try it out locally? Follow the below guide

* Create an OCI Artifact for the Operator which you can later use to deploy in your cluster.
    ```
    docker buildx build -t <remote-registry>/<image-name>:<image-tag> . 
    ```

* Push your image to the remote registry.
    ```
    docker push <remote-registry>/<image-name>:<image-tag> 
    ```

* You can then use this image to deploy any changes to operator.
