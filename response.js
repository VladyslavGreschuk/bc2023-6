exports.status = (status, values, res) => {
    const data = {
        "status": status,
        "values": values
    }

    res.json(data);
    res.end();
}