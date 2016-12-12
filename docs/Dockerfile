FROM ruby:latest

RUN apt update \
	&& apt install -y --no-install-recommends \
		npm \
	&& rm -rf /var/lib/apt/lists/* \
	&& gem install bundler github-pages \
	&& mkdir /www

WORKDIR /www

ENTRYPOINT ["bundle", "exec", "jekyll", "serve", "--incremental"]
CMD [ "--incremental", "--host", "0.0.0.0" ]
