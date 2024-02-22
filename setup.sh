#! /bin/bash
set -e

CLUSTERS=(
  scenario_three
  scenario_two
  scenario_one
)

if (! command -v terraform >> /dev/null); then
    echo "Installing terraform"
    sudo yum install -y yum-utils
    sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo
    sudo yum -y install terraform
else
    echo "terraform found, skipping installation"
    terraform version
fi

if (! command -v helm >> /dev/null); then
    echo "Installing helm"
    curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
    chmod 700 get_helm.sh
    ./get_helm.sh
    rm get_helm.sh
else
    echo "helm found, skipping installation"
    helm version
fi

if (! command -v kubectl >> /dev/null); then
    echo "Installing kubectl"
    curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
    sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
    echo "alias k=kubectl" >> /home/ec2-user/.bashrc
    source /home/ec2-user/.bashrc
else
    echo "kubectl found, skipping installation"
    kubectl version --client=true
fi

if (! test -f /usr/local/bin/kctx &&  ! test -f /usr/local/bin/kns); then
    echo "Installing kubectx"
    sudo git clone https://github.com/ahmetb/kubectx /opt/kubectx
    sudo ln -s /opt/kubectx/kubectx /usr/local/bin/kctx
    sudo ln -s /opt/kubectx/kubens /usr/local/bin/kns
    
else
    echo "kubectx found, skipping installation"
fi

if (! test -f .terraform.lock.hcl); then
    terraform init
fi

terraform apply -auto-approve

REGION=$(terraform output -json region | jq -r ".")

terraform output -json asg_name | jq -r '.[]' | while read -r asg; do aws autoscaling set-desired-capacity --region $REGION --auto-scaling-group-name $asg --desired-capacity 2; done

for resource in "${CLUSTERS[@]}"; do
    aws eks update-kubeconfig --name ${resource} --region $REGION
done