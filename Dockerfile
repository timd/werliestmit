FROM nginx:alpine
COPY nginx.conf /etc/nginx/templates/default.conf.template
COPY index.html impressum.html datenschutz.html data.json gemeinden.topojson /usr/share/nginx/html/
