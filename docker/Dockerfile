FROM bretfisher/jekyll-serve
 
# Copy files in blog's root dir to /srv/jekyll
# docker-compose.yml's context will be ..
COPY . /srv/jekyll
 
WORKDIR /srv/jekyll
 
RUN bundle install

RUN git config --global --add safe.directory /srv/jekyll
 
CMD ["jekyll", "serve", "--host", "0.0.0.0", "--port", "4000", "--watch"]
