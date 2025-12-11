// stores/sessionStore.js

// Objeto em memória onde guardamos todas as sessões
const sessions = {};

// Exportamos um objeto com funções para manipular sessões
module.exports = {

    // Guarda uma sessão nova ou atualiza uma existente
    set: (sid, data) => {
        sessions[sid] = data;
    },

    // Vai buscar uma sessão pelo ID do cookie
    get: (sid) => {
        return sessions[sid];
    },

    // Remove a sessão (logout)
    delete: (sid) => {
        delete sessions[sid];
    }
};
