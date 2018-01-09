provider "aws" {
	region = "${var.aws_region}"
	profile = "${var.aws_profile}"
}

#IAM
#S3 access: creates a role in IAM to access the S3 resources
resource "aws_iam_instance_profile" "s3_access" {
	name 	= "s3_access"
	roles 	= ["${aws_iam_role.s3_access.name}"]
}

resource "aws_iam_role_policy" "s3_access_policy" {
	name 	= "s3_access_policy"
	role 	= "${aws_iam_role.s3_access.id}"
	policy 	= <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:*",
      "Resource": "*"
    }
  ]
}
EOF
}


#Allows for EC2 instances to have the S3 access role attached to them.
resource "aws_iam_role" "s3_access" {
	name = "s3_access"
	assume_role_policy = <<EOF
{
	"Version": "2012-10-17",
	"Statement": [
	{
		"Action": "sts:AssumeRole",
		"Principal": {
			"Service": "ec2.amazonaws.com"
	},
		"Effect": "Allow",
		"Sid": ""
		}
	]
}
}


#Create the VPC

resource "aws_vpc "vpc" {
	cidr_block = "10.1.0.0/16"
}


#Create the Internet Gateway and reference the vpc variable above
resource "aws_internet_gateway" "internet_gateway" {
	vpc_id = "${aws_vpc.vpc.id}"
}

#Create public route table within the created vpc and attach the IGW giving it a route to the internet
resource "aws_route_table" "public" {
	vpc_id = "${aws_vpc.vpc.id}"
	route {
		cidr_block = "0.0.0.0/0"
		gateway_id = "${aws_internet_gateway.internet_gateway.id}"
		}
	tags {
		Name = "public"
	}
}

#Create the private route table
resource "aws_default_route_table" "private" {
	default_route_table_id = "${aws_vpc.vpc.default_route_table_id}"
	tags {
		Name = "private"
	}
}


#Create public subnet to launch instances into
resource "aws_subnet" "public" {
	vpc_id = "${aws_vpc.vpc.id}"
	cidr_block = "10.1.1.0/24"
	map_public_ip_on_launch = true
	availability_zone = "us-east-1d"

	tags {
        Name = "public"
	}
}

#Create private subnet 1
resource "aws_subnet" "private1" {
	vpc_id = "${aws_vpc.vpc.id}"
	cidr_block = "10.1.2.0/24"
	map_public_ip_on_launch = false #because we want to keep these private
	availability_zone = "us-east-1a"

	tags {
		Name = "private1"
	}
}


#Create private subnet 2
resource "aws_subnet" "private2" {
	vpc_id = "${aws_vpc.vpc.id}"
	cidr_block = "10.1.3.0/24"
	map_public_ip_on_launch = false #because we want to keep these private
	availability_zone = "us-east-1c"

	tags {
		Name = "private2"
	}
}

#Create a S3 VPC endpoint.
#This will allow routing to and from S3 to the private instances without having a S3 ip address added.
resource "aws_vpc_endpoint" "private-3" {
	vpc_id = "${aws_vpc.vpc.id}"
	service_name = "com.amazonaws.${var.aws_region}.s3" #Service name is s3 and region backwards when creating an endpoint.
	route_table_ids = ["${aws_vpc.vpc.main_route_table_id}", "${aws_route_table.public.id}"]
	policy = <<POLICY
{
	"Statement": [
		{
			"Action": "*",
			"Effect": "Allow",
			"Resource": "*",
			"Principal": "*"
		}
	]
}
POLICY
}


#Create RDS subnet 1
resource "aws_subnet" "rds1" {
	vpc_id = "${aws_vpc.vpc.id}"
	cidr_block = "10.1.4.0/24"
	map_public_ip_on_launch = false #because we want to keep these private
	availability_zone = "us-east-1a"

	tags {
		Name = "rds1"
	}
}

#Create RDS subnet 2
resource "aws_subnet" "rds2" {
	vpc_id = "${aws_vpc.vpc.id}"
	cidr_block = "10.1.5.0/24"
	map_public_ip_on_launch = false #because we want to keep these private
	availability_zone = "us-east-1c"

	tags {
		Name = "rds2"
	}
}

#Create RDS subnet 3
resource "aws_subnet" "rds3" {
	vpc_id = "${aws_vpc.vpc.id}"
	cidr_block = "10.1.6.0/24"
	map_public_ip_on_launch = false #because we want to keep these private
	availability_zone = "us-east-1d"

	tags {
		Name = "rds3"
	}
}

#Public subnet route table associations. 
resource "aws_route_table_association" "public_assoc" {
	subnet_id = "${aws_subnet.public.id}"
	route_table_id = "${aws_route_table.public.id}"
}

#Private subnets will need to be associated w/public subnets to be able to have traffic routed from load balancers and since the private #instances do not have public ips.
resource "aws_route_table_association" "private1_assoc" {
	subnet_id = "${aws_subnet.private1.id}"
	route_table_id = "${aws_route_table.public.id}"
}

resource "aws_route_table_association" "private2_assoc" {
	subnet_id = "${aws_subnet.private2.id}"
	route_table_id = "${aws_route_table.public.id}"
}

#Create RDS Database subnet group
resource "aws_db_subnet_group" "rds_subnetgroup" {
	name = "rds_subnetgroup"
	subnet_ids = ["${aws_subnet.rds1.id}", "${aws_subnet.rds2.id}", "${aws_subnet.rds3.id}"]

	tags {
		Name = "rds_sng"
	}
}


#Create Security groups
#Public security group: will allow access from internet to port 80 http, and only from your IP to port 22 SSH.
resource "aws_security_group" "public"{
	name = "sg_public"
	description = "Used for public and private instances for load balancer access"
	vpc_id = "${aws_vpc.vpc.id}"

	#SSH access for only your ip
	ingress {
		from_port	= 22
		to_port		= 22
		protocol	= "tcp"
		cidr_blocks	= ["${var.localip}"]
	}

	#HTTP access rule
	ingress {
		from_port	= 80
		to_port		= 80
		protocol	= "tcp"
		cidr_blocks	= ["0.0.0.0/0"]
	}

	#Outbound internet access
	egress {
		from_port	= 0
		to_port		= 0
		protocol	= "-1"
		cidr_blocks = ["0.0.0.0/0"]
	}
}

#Create Private Security Group

resource "aws_security_group" "private" {
	name 		= "sg_private"
	description = "Used for private instances"
	vpc_id 		= "${aws_vpc.vpc.id}"

	#Give access from other security groups
	ingress {
		from_port	= 0
		to_port		= 0
		protocol	= "-1"
		cidr_blocks	= ["10.1.0.0/16"]
	}

	egress {
		from_port	= 0
		to_port		= 0
		protocol	= "-1"
		cidr_blocks	= ["0.0.0.0/0"]
	}
}

#Create RDS Security Group
resource "aws_security_group" "RDS" {
	name 		= "sg_rds"
	description	= "Used for DB instances"
	vpc_id		= "${aws_vpc.vpc.id}"

	#SQL access from public/private security group
	ingress {
		from_port		= 3306
		to_port			= 3306
		protocol		= "tcp"
		security_groups	= ["${aws_security_group.public.id}", "${aws_security_group.private.id}"]
	}
}

#S3 CODE BUCKET
resource "aws_s3_bucket" "code" {
	bucket = "${var.domain_name}_codes7699"
	acl = "private"
	force_destroy = true
	tags {
		Name = "code bucket"
	}
}




#COMPUTE
#Create DB instance
resource "aws_db_instance" "db" {
	allocated_storage		= 10
	engine					= "mysql"
	engine_version			= "5.6.27"
	engine_class			= "${var.db_instance_class}"
	name  					= "${var.dbname}"
	username				= "${var.dbuser}"
	password				= "${var.dbpassword}"
	db_subnet_group_name	= "${aws_db_subnet_group.rds_subnetgroup.name}"
	vpc_security_group_ids	= ["${aws_security_group.RDS.id}"]
}


#Create key pair
resource "aws_key_pair" "auth" {
	key_name = "${var.key_name}"
	public_key = "${file(var.public_key_path)}"
}

#DEV SERVER
resource "aws_instance" "dev" {
	instance_type 	= "${var.dev_instance_type}"
	ami 			= "${var.dev_ami}"
	tags {
		Name = "dev"
	}

	key_name 				= "${aws_key_pair.auth.id}"
	vpc_security_group_ids	= ["${aws_security_group.public.id}"]
	iam_instance_profile 	= "${aws_iam_instance_profile.s3_access.id}"
	subnet_id 				= "${aws_subnet.public.id}"


#Run the local provisioner to export the public ip address of new dev instance and the name of the code bucket to a file called 'aws_hosts'
	provisioner "local-exec" {
		command = <<EOD
cat <<EOF > aws_hosts 
[dev]
${aws_instance.dev.public_ip} 
[dev:vars] 
s3code=${aws_s3_bucket.code.bucket} 
EOF
EOD
	}

#Now we need to call the Ansible playbook using 'aws_hosts' to define the target.
	provisioner "local-exec" {
		command = "sleep 6m && ansible-playbook -i aws_hosts wordpress.yml"
	}
}



  
#LOAD BALANCER
resource "aws_elb" "prod" {
	name = "${var.domain_name}-prod-elb"
	subnets = ["${aws_subnet.private1.id}", "${aws_subnet.private2.id}"]
	security_groups = ["${aws_security_group.public.id}"]
	listener {
		instance_port = 80
		instance_protool = "http"
		lb_port = 80
		lb_protocol = "http"
	}
	health_check {
		healthy_threshold = "${var.elb_healthy_threshold}"
		unhealthy_threshold = "${var.elb_unhealthy_threshold}"
		timeout = "${var.elb_timeout}"
		target = "HTTP:80/"
		interval = "${var.elb_interval}"
	}

	cross_zone_load_balancing = true
	idle_timeout = 400
	connection_draining = true
	connection_drainining_timeout = 400

	tags {
		Name = "${var.domain_name}-prod-elb"
	}
}

#Launch AMI from dev instance using random prefix and push local provisioner to run a cron job to get the instances to pull
#code update from the S3 code bucket every 5 minutes. So if you update the dev instance, it will get a code push to the prod instance
#every 5 mins.
resource "random_id" "ami" {
	byte_length = 8
}
resource "aws_ami_from_instance" "golden" {
    name = "ami-${random_id.ami.b64}"
    source_instance_id = "${aws_instance.dev.id}"
    provisioner "local-exec" {
		command = "cat <<EOF > userdata
			#!/bin/bash
			/usr/bin/aws s3 sync s3://${aws_s3_bucket.code.bucket} /var/www/html/
			/bin/touch /var/spool/cron/root
			sudo /bin/echo '*/5 * * * * aws s3 sync s3://${aws_s3_bucket.code.bucket} /var/www/html/' >> /var/spool/cron/root
			EOF"
	}
}


#Create launch configuration for ASG
resource "aws_launch_configuration" "lc" {
	name_prefix = "lc-"
	image_id = "${aws_ami_from_instance.golden.id}"
	instance_type = "${var.lc_instance_type}"
	security_groups = ["${aws_security_group.private.id}"]
	iam_instance_profile = "${aws_iam_instance_profile.s3_access.id}"
	key_name = "${aws_key_pair.auth.id}"
	user_data = "${file("userdata")}"
	lifecycle {
		create_before_destroy = true
	}
}

#Autoscaling Group
resource "random_id" "asg" {
	byte_length = 8
}

resource "aws_autoscaling_group" "asg" {
	availability_zones = ["${var.aws_region}a", "${var.aws_region}c"]
	name = "asg-${aws_launch_configuration.lc.id}"
	max_size = "${var.asg_max}"
	min_size = "${var.asg_min}"
	health_check_grace_period = "${var.asg_grace}"
	health_check_type = "${var.asg_hct}"
	desired_capacity = "${var.asg_cap}"
	force_delete = true
	load_balancers = ["${aws_elb.prod.id}"]
	vpc_zone_identifier = ["${aws_subnet.private1.id}", "${aws_subnet.private2.id}"]
	launch_configuration = "${aws_launch_configuration.lc.name}"

	tag {
		key = "Name"
		value = "asg-instance"
		propagate_at_launch = true
		}

	lifecycle {
		create_before_destroy = true
	}
}

#Route53 records
#Setup the primary zone
resource "aws_route53_zone" "primary" {
	name = "${var.domain_name}.com"
	delegation_set_id = "${var.delegation_set}"
}

#Create Route53 www record that points to load balancer
resource "aws_route53_record" "www" {
	zone_id = "${aws_route53_zone.primary.zone_id}"
	name = "www.${var.domain_name}.com"
	type = "A"

	alias {
		name = "${aws_elb.prod.dns_name}"
		zone_id = "${aws_elb.prod.zone_id}"
		evaluate_target_health = false
	}
}

#Route53 dev record that will point to dev server
resource "aws_route53_record" "dev" {
	zone_id = "${aws_route53_zone.primary.zone_id}"
	name = "dev.${var.domain_name}.com"
	type = "A"
	ttl = "300"
	records = ["${aws_instance.dev.public_ip}"]
}


#db cname record which will allow wordpress to reference it incase the db instance ip changes
resource "aws_route53_record" "db" {
	zone_id = "${aws_route53_zone.primary.id}"
	name = "db.${var.domain_name}com"
	type = "CNAME"
	ttl = "300"
	records = ["${aws_db_instance.db.address}"]
}