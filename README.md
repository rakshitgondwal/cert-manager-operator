## Kubernetes Cert Manager Operator

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


#### Want to try it out locally? Follow the below guide

* Create an OCI Artifact for the Operator which you can later use to deploy in your cluster.
    ```
    docker buildx build -t <remote-registry>/<image-name>:<image-tag> . 
    ```

* Push your image to the remote registry.
    ```
    docker push <remote-registry>/<image-name>:<image-tag> 
    ```