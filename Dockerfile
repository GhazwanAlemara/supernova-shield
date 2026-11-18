FROM node:20-alpine

WORKDIR /app
COPY package.json README.md LICENSE ./
COPY src/ ./src/
COPY bin/ ./bin/

RUN npm link --ignore-scripts

ENTRYPOINT ["supernova-shield"]
CMD ["demo"]
