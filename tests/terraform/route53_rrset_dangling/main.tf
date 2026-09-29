resource "random_pet" "zone" {
  prefix = "c7n-dangling"
  length = 2
}

resource "aws_route53_zone" "public" {
  name = "${random_pet.zone.id}.net"
}

resource "aws_route53_record" "gone" {
  zone_id = aws_route53_zone.public.zone_id
  name    = "gone.${aws_route53_zone.public.name}"
  type    = "CNAME"
  ttl     = 300
  records = ["gone.example.net"]
}

resource "aws_route53_record" "no_address" {
  zone_id = aws_route53_zone.public.zone_id
  name    = "no-address.${aws_route53_zone.public.name}"
  type    = "CNAME"
  ttl     = 300
  records = ["no-address.example.net"]
}

resource "aws_route53_record" "alive" {
  zone_id = aws_route53_zone.public.zone_id
  name    = "alive.${aws_route53_zone.public.name}"
  type    = "CNAME"
  ttl     = 300
  records = ["alive.example.net"]
}

resource "aws_route53_record" "flaky" {
  zone_id = aws_route53_zone.public.zone_id
  name    = "flaky.${aws_route53_zone.public.name}"
  type    = "CNAME"
  ttl     = 300
  records = ["flaky.example.net"]
}

resource "aws_route53_record" "web" {
  zone_id = aws_route53_zone.public.zone_id
  name    = "web.${aws_route53_zone.public.name}"
  type    = "A"
  ttl     = 300
  records = ["192.0.2.10"]
}

resource "aws_route53_record" "alias" {
  zone_id = aws_route53_zone.public.zone_id
  name    = "alias.${aws_route53_zone.public.name}"
  type    = "A"

  alias {
    name                   = aws_route53_record.web.fqdn
    zone_id                = aws_route53_zone.public.zone_id
    evaluate_target_health = false
  }
}

resource "aws_vpc" "private" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_route53_zone" "private" {
  name = "${random_pet.zone.id}.internal"

  vpc {
    vpc_id = aws_vpc.private.id
  }
}

resource "aws_route53_record" "private" {
  zone_id = aws_route53_zone.private.zone_id
  name    = "internal.${aws_route53_zone.private.name}"
  type    = "CNAME"
  ttl     = 300
  records = ["private-target.example.net"]
}
